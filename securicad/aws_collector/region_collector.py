# Copyright 2019-2021 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

from boto3.session import Session  # type: ignore
from botocore.client import BaseClient  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from securicad.aws_collector import utils

log = logging.getLogger("securicad-aws-collector")


def collect(
    credentials: Dict[str, str],
    region_data: Dict[str, Any],
    include_inspector: bool,
    threads: Optional[int],
) -> None:
    session = Session(**credentials, region_name=region_data["region_name"])

    region_data.update(get_region_data(session, include_inspector, threads))


def get_region_data(
    session: Session, include_inspector: bool, threads: Optional[int]
) -> Dict[str, Any]:
    client_lock: Lock = Lock()
    client_cache: Dict[str, BaseClient] = {}
    unpaginated = utils.get_unpaginated(session, client_lock, client_cache)
    paginate = utils.get_paginate(session, client_lock, client_cache)
    fake_paginate = utils.get_fake_paginate(session, client_lock, client_cache)

    tasks: List[Callable[[], Tuple[List[str], Any]]] = []

    def add_task(task: Callable[[], Tuple[List[str], Any]], *services: str) -> None:
        for service in services:
            if session.region_name not in session.get_available_regions(service):
                log.info(
                    f'Region "{session.region_name}" does not support service "{service}"'
                )
                return
        tasks.append(task)

    def ec2_describe_instances() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-instances, describe-images")

        def get_image_id_to_instances(
            reservations: List[Dict[str, Any]]
        ) -> Dict[str, List[Dict[str, Any]]]:
            image_id_to_instances: Dict[str, List[Dict[str, Any]]] = {}
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["ImageId"] not in image_id_to_instances:
                        image_id_to_instances[instance["ImageId"]] = []
                    image_id_to_instances[instance["ImageId"]].append(instance)
            return image_id_to_instances

        def get_images(image_ids: List[str]) -> List[Dict[str, Any]]:
            return unpaginated("ec2", "describe_images", param={"ImageIds": image_ids})[
                "Images"
            ]

        def set_is_windows(reservations: List[Dict[str, Any]]) -> None:
            image_id_to_instances = get_image_id_to_instances(reservations)
            images = get_images(list(image_id_to_instances))
            for image in images:
                is_windows = image.get("Platform") == "windows"
                for instance in image_id_to_instances.get(image["ImageId"], []):
                    instance["IsWindows"] = is_windows

        reservations = paginate("ec2", "describe_instances", key="Reservations")
        set_is_windows(reservations)
        # TODO: Change to ["ec2", "Reservations"]
        return ["instance", "Reservations"], reservations

    add_task(ec2_describe_instances, "ec2")

    def ec2_describe_network_interfaces() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-network-interfaces")
        # TODO: Change to ["ec2", "NetworkInterfaces"]
        return ["interface", "NetworkInterfaces"], paginate(
            "ec2", "describe_network_interfaces", key="NetworkInterfaces"
        )

    add_task(ec2_describe_network_interfaces, "ec2")

    def ec2_describe_security_groups() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-security-groups")
        # TODO: Change to ["ec2", "SecurityGroups"]
        return ["securitygroup", "SecurityGroups"], paginate(
            "ec2", "describe_security_groups", key="SecurityGroups"
        )

    add_task(ec2_describe_security_groups, "ec2")

    def ec2_describe_subnets() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-subnets")
        # TODO: Change to ["ec2", "Subnets"]
        return ["subnet", "Subnets"], paginate("ec2", "describe_subnets", key="Subnets")

    add_task(ec2_describe_subnets, "ec2")

    def ec2_describe_network_acls() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-network-acls")
        # TODO: Change to ["ec2", "NetworkAcls"]
        return ["acl", "NetworkAcls"], paginate(
            "ec2", "describe_network_acls", key="NetworkAcls"
        )

    add_task(ec2_describe_network_acls, "ec2")

    def ec2_describe_vpcs() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-vpcs")
        # TODO: Change to ["ec2", "Vpcs"]
        return ["vpc", "Vpcs"], paginate("ec2", "describe_vpcs", key="Vpcs")

    add_task(ec2_describe_vpcs, "ec2")

    def ec2_describe_vpc_peering_connections() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-vpc-peering-connections")
        # TODO: Change to ["ec2", "VpcPeeringConnections"]
        return ["vpcpeering", "VpcPeeringConnections"], paginate(
            "ec2", "describe_vpc_peering_connections", key="VpcPeeringConnections"
        )

    add_task(ec2_describe_vpc_peering_connections, "ec2")

    def ec2_describe_internet_gateways() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-internet-gateways")
        # TODO: Change to ["ec2", "InternetGateways"]
        return ["igw", "InternetGateways"], paginate(
            "ec2", "describe_internet_gateways", key="InternetGateways"
        )

    add_task(ec2_describe_internet_gateways, "ec2")

    def ec2_describe_vpn_gateways() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-vpn-gateways")
        # TODO: Change to ["ec2", "VpnGateways"]
        return ["vgw", "VpnGateways"], unpaginated("ec2", "describe_vpn_gateways")[
            "VpnGateways"
        ]

    add_task(ec2_describe_vpn_gateways, "ec2")

    def ec2_describe_nat_gateways() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-nat-gateways")
        # TODO: Change to ["ec2", "NatGateways"]
        return ["ngw", "NatGateways"], paginate(
            "ec2", "describe_nat_gateways", key="NatGateways"
        )

    add_task(ec2_describe_nat_gateways, "ec2")

    def ec2_describe_route_tables() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-route-tables")
        # TODO: Change to ["ec2", "RouteTables"]
        return ["routetable", "RouteTables"], paginate(
            "ec2", "describe_route_tables", key="RouteTables"
        )

    add_task(ec2_describe_route_tables, "ec2")

    def ec2_describe_vpc_endpoints() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-vpc-endpoints")
        # TODO: Change to ["ec2", "VpcEndpoints"]
        return ["vpcendpoint", "VpcEndpoints"], paginate(
            "ec2", "describe_vpc_endpoints", key="VpcEndpoints"
        )

    add_task(ec2_describe_vpc_endpoints, "ec2")

    def ec2_describe_volumes() -> Tuple[List[str], Any]:
        log.debug("Executing ec2 describe-volumes")
        # TODO: Change to ["ec2", "Volumes"]
        return ["ebs", "Volumes"], paginate("ec2", "describe_volumes", key="Volumes")

    add_task(ec2_describe_volumes, "ec2")

    def ec2_describe_transit_gateways() -> Tuple[List[str], Any]:
        log.debug(
            "Executing ec2 describe-transit-gateways, describe-transit-gateway-attachments, get-transit-gateway-attachment-propagations, describe-transit-gateway-peering-attachments, describe-transit-gateway-route-tables, search-transit-gateway-routes, get-transit-gateway-prefix-list-references, get-transit-gateway-route-table-associations, get-transit-gateway-route-table-propagations, describe-transit-gateway-vpc-attachments"
        )

        def get_attachments() -> Dict[str, Dict[str, Dict[str, Any]]]:
            def get_attachment_propagations(attachment_id: str) -> List[Dict[str, Any]]:
                try:
                    return paginate(
                        "ec2",
                        "get_transit_gateway_attachment_propagations",
                        key="TransitGatewayAttachmentPropagations",
                        param={"TransitGatewayAttachmentId": attachment_id},
                    )
                except ClientError as e:
                    if (
                        e.response["Error"]["Code"]
                        != "InvalidTransitGatewayAttachmentID.NotFound"
                    ):
                        raise
                    return []

            attachments = paginate(
                "ec2",
                "describe_transit_gateway_attachments",
                key="TransitGatewayAttachments",
                param={
                    "Filters": [
                        {"Name": "association.state", "Values": ["associated"]},
                        {"Name": "state", "Values": ["available"]},
                    ]
                },
            )
            res: Dict[str, Dict[str, Dict[str, Any]]] = {}
            for attachment in attachments:
                tgw_id = attachment["TransitGatewayId"]
                attachment_id = attachment["TransitGatewayAttachmentId"]
                attachment["Propagations"] = get_attachment_propagations(attachment_id)
                if tgw_id not in res:
                    res[tgw_id] = {}
                res[tgw_id][attachment_id] = attachment
            return res

        def get_peering_attachments() -> Dict[str, Dict[str, Any]]:
            peering_attachments = paginate(
                "ec2",
                "describe_transit_gateway_peering_attachments",
                key="TransitGatewayPeeringAttachments",
            )
            res: Dict[str, Dict[str, Any]] = {}
            for peering_attachment in peering_attachments:
                attachment_id = peering_attachment["TransitGatewayAttachmentId"]
                res[attachment_id] = peering_attachment
            return res

        def get_route_tables() -> Dict[str, Dict[str, Dict[str, Any]]]:
            def get_routes(route_table_id: str) -> List[Dict[str, Any]]:
                param = {
                    "TransitGatewayRouteTableId": route_table_id,
                    "Filters": [
                        {
                            "Name": "route-search.subnet-of-match",
                            "Values": ["0.0.0.0/0", "::/0"],
                        }
                    ],
                }
                return unpaginated("ec2", "search_transit_gateway_routes", param=param)[
                    "Routes"
                ]

            def get_prefix_list_references(route_table_id: str) -> List[Dict[str, Any]]:
                return paginate(
                    "ec2",
                    "get_transit_gateway_prefix_list_references",
                    key="TransitGatewayPrefixListReferences",
                    param={"TransitGatewayRouteTableId": route_table_id},
                )

            def get_associations(route_table_id: str) -> List[Dict[str, Any]]:
                return paginate(
                    "ec2",
                    "get_transit_gateway_route_table_associations",
                    key="Associations",
                    param={"TransitGatewayRouteTableId": route_table_id},
                )

            def get_propagations(route_table_id: str) -> List[Dict[str, Any]]:
                return paginate(
                    "ec2",
                    "get_transit_gateway_route_table_propagations",
                    key="TransitGatewayRouteTablePropagations",
                    param={"TransitGatewayRouteTableId": route_table_id},
                )

            route_tables = paginate(
                "ec2",
                "describe_transit_gateway_route_tables",
                key="TransitGatewayRouteTables",
            )
            res: Dict[str, Dict[str, Dict[str, Any]]] = {}
            for route_table in route_tables:
                tgw_id = route_table["TransitGatewayId"]
                route_table_id = route_table["TransitGatewayRouteTableId"]
                route_table["Routes"] = get_routes(route_table_id)
                route_table["PrefixListReferences"] = get_prefix_list_references(
                    route_table_id
                )
                route_table["Associations"] = get_associations(route_table_id)
                route_table["Propagations"] = get_propagations(route_table_id)
                if tgw_id not in res:
                    res[tgw_id] = {}
                res[tgw_id][route_table_id] = route_table
            return res

        def get_vpc_attachments() -> Dict[str, Dict[str, Dict[str, Any]]]:
            vpc_attachments = paginate(
                "ec2",
                "describe_transit_gateway_vpc_attachments",
                key="TransitGatewayVpcAttachments",
            )
            res: Dict[str, Dict[str, Dict[str, Any]]] = {}
            for vpc_attachment in vpc_attachments:
                tgw_id = vpc_attachment["TransitGatewayId"]
                attachment_id = vpc_attachment["TransitGatewayAttachmentId"]
                if tgw_id not in res:
                    res[tgw_id] = {}
                res[tgw_id][attachment_id] = vpc_attachment
            return res

        transit_gateways = paginate(
            "ec2", "describe_transit_gateways", key="TransitGateways"
        )
        attachments = get_attachments()
        peering_attachments = get_peering_attachments()
        route_tables = get_route_tables()
        vpc_attachments = get_vpc_attachments()

        for transit_gateway in transit_gateways:
            tgw_id = transit_gateway["TransitGatewayId"]
            transit_gateway["Attachments"] = list(attachments.get(tgw_id, {}).values())
            transit_gateway["PeeringAttachments"] = [
                peering_attachments[attachment_id]
                for attachment_id in attachments.get(tgw_id, {})
                if attachment_id in peering_attachments
            ]
            transit_gateway["RouteTables"] = list(route_tables.get(tgw_id, {}).values())
            transit_gateway["VpcAttachments"] = list(
                vpc_attachments.get(tgw_id, {}).values()
            )

        return ["ec2", "TransitGateways"], transit_gateways

    add_task(ec2_describe_transit_gateways, "ec2")

    def elb_describe_load_balancers() -> Tuple[List[str], Any]:
        log.debug("Executing elb describe-load-balancers")
        return ["elb", "LoadBalancerDescriptions"], paginate(
            "elb", "describe_load_balancers", key="LoadBalancerDescriptions"
        )

    add_task(elb_describe_load_balancers, "elb")

    def elbv2_describe_load_balancers() -> Tuple[List[str], Any]:
        log.debug(
            "Executing elbv2 describe-load-balancers, describe-listeners, describe-rules"
        )

        def get_rules(listener_arn: str) -> List[Dict[str, Any]]:
            try:
                return paginate(
                    "elbv2",
                    "describe_rules",
                    key="Rules",
                    param={"ListenerArn": listener_arn},
                )
            except ClientError as e:
                if e.response["Error"]["Code"] != "ListenerNotFoundException":
                    raise
            return []

        def get_listeners(load_balancer_arn: str) -> List[Dict[str, Any]]:
            listeners = paginate(
                "elbv2",
                "describe_listeners",
                key="Listeners",
                param={"LoadBalancerArn": load_balancer_arn},
            )
            for listener in listeners:
                listener["Rules"] = get_rules(listener["ListenerArn"])
            return listeners

        load_balancers = paginate(
            "elbv2", "describe_load_balancers", key="LoadBalancers"
        )
        for load_balancer in load_balancers:
            load_balancer["Listeners"] = get_listeners(load_balancer["LoadBalancerArn"])
        return ["elbv2", "LoadBalancers"], load_balancers

    add_task(elbv2_describe_load_balancers, "elbv2")

    def elbv2_describe_target_groups() -> Tuple[List[str], Any]:
        log.debug("Executing elbv2 describe-target-groups, describe-target-health")

        def get_targets(target_group_arn: str) -> List[Dict[str, Any]]:
            target_health_descriptions = unpaginated(
                "elbv2",
                "describe_target_health",
                param={"TargetGroupArn": target_group_arn},
            )["TargetHealthDescriptions"]
            return [
                target_health_description["Target"]
                for target_health_description in target_health_descriptions
            ]

        target_groups = paginate("elbv2", "describe_target_groups", key="TargetGroups")
        for target_group in target_groups:
            target_group["Targets"] = get_targets(target_group["TargetGroupArn"])
        return ["elbv2", "TargetGroups"], target_groups

    add_task(elbv2_describe_target_groups, "elbv2")

    def autoscaling_describe_launch_configurations() -> Tuple[List[str], Any]:
        log.debug("Executing autoscaling describe-launch-configurations")
        # TODO: Change to ["autoscaling", "LaunchConfigurations"]
        return ["launchconfigs", "LaunchConfigurations"], paginate(
            "autoscaling", "describe_launch_configurations", key="LaunchConfigurations"
        )

    add_task(autoscaling_describe_launch_configurations, "autoscaling")

    def rds_describe_db_instances() -> Tuple[List[str], Any]:
        log.debug("Executing rds describe-db-instances")
        # TODO: Change to ["rds", "DBInstances"]
        return ["rds", "Instances", "DBInstances"], paginate(
            "rds", "describe_db_instances", key="DBInstances"
        )

    add_task(rds_describe_db_instances, "rds")

    def rds_describe_db_subnet_groups() -> Tuple[List[str], Any]:
        log.debug("Executing rds describe-db-subnet-groups")
        # TODO: Change to ["rds", "DBSubnetGroups"]
        return ["rds", "SubnetGroups", "DBSubnetGroups"], paginate(
            "rds", "describe_db_subnet_groups", key="DBSubnetGroups"
        )

    add_task(rds_describe_db_subnet_groups, "rds")

    def lambda_list_functions() -> Tuple[List[str], Any]:
        log.debug("Executing lambda list-functions")
        return ["lambda", "Functions"], paginate(
            "lambda", "list_functions", key="Functions"
        )

    add_task(lambda_list_functions, "lambda")

    def kms_list_keys() -> Tuple[List[str], Any]:
        log.debug("Executing kms list-keys, get-key-policy")

        def get_policy(key_id: str) -> Dict[str, Any]:
            return json.loads(
                unpaginated(
                    "kms",
                    "get_key_policy",
                    param={"KeyId": key_id, "PolicyName": "default"},
                )["Policy"]
            )

        keys = paginate("kms", "list_keys", key="Keys")
        for key in keys:
            key["Policy"] = get_policy(key["KeyId"])
        return ["kms", "Keys"], keys

    add_task(kms_list_keys, "kms")

    def inspector_describe_findings() -> Tuple[List[str], Any]:
        log.debug(
            "Executing inspector list-assessment-runs, describe-assessment-runs, list-rules-packages, describe-rules-packages, list-findings, describe-findings"
        )

        # Filter findings to only return findings and runs from the last 365 days
        now = datetime.now()
        time_range = {"beginDate": now - timedelta(days=365), "endDate": now}

        def get_assessment_run_arns() -> List[str]:
            # List all runs within the timeframe
            return paginate(
                "inspector",
                "list_assessment_runs",
                key="assessmentRunArns",
                param={"filter": {"completionTimeRange": time_range}},
            )

        def get_assessment_runs() -> List[Dict[str, Any]]:
            assessment_run_arns = get_assessment_run_arns()
            if not assessment_run_arns:
                return []
            return fake_paginate(
                "inspector",
                "describe_assessment_runs",
                request_key="assessmentRunArns",
                response_key="assessmentRuns",
                n=10,
                items=assessment_run_arns,
            )

        def get_latest_assessment_run_arn() -> Optional[str]:
            # Get the latest run with findings in it
            assessment_runs = get_assessment_runs()
            sorted_assessment_runs = sorted(
                assessment_runs,
                key=lambda assessment_run: assessment_run["completedAt"],
                reverse=True,
            )
            for assessment_run in sorted_assessment_runs:
                finding_count = sum(assessment_run.get("findingCounts", {}).values())
                if finding_count > 0:
                    return assessment_run["arn"]
            return None

        def get_rules_package_arns() -> List[str]:
            return paginate("inspector", "list_rules_packages", key="rulesPackageArns")

        def get_rules_packages() -> List[Dict[str, Any]]:
            rules_package_arns = get_rules_package_arns()
            if not rules_package_arns:
                return []
            return fake_paginate(
                "inspector",
                "describe_rules_packages",
                request_key="rulesPackageArns",
                response_key="rulesPackages",
                n=10,
                items=rules_package_arns,
            )

        def get_supported_rules_package_arns() -> List[str]:
            # Get all supported rule packages
            rules_packages = get_rules_packages()
            rules_package_arns = []
            for rules_package in rules_packages:
                if "Common Vulnerabilities and Exposures" in rules_package["name"]:
                    rules_package_arns.append(rules_package["arn"])
                if "Network Reachability" in rules_package["name"]:
                    rules_package_arns.append(rules_package["arn"])
            return rules_package_arns

        def get_finding_arns() -> List[str]:
            # List all findings within the timeframe and the latest run
            # Filter to only include supported finding types
            assessment_run_arn = get_latest_assessment_run_arn()
            if not assessment_run_arn:
                return []
            rules_package_arns = get_supported_rules_package_arns()
            if not rules_package_arns:
                return []
            return paginate(
                "inspector",
                "list_findings",
                key="findingArns",
                param={
                    "assessmentRunArns": [assessment_run_arn],
                    "filter": {
                        "rulesPackageArns": rules_package_arns,
                        "creationTimeRange": time_range,
                    },
                },
            )

        def get_findings() -> List[Dict[str, Any]]:
            finding_arns = get_finding_arns()
            if not finding_arns:
                return []
            return fake_paginate(
                "inspector",
                "describe_findings",
                request_key="findingArns",
                response_key="findings",
                n=10,
                items=finding_arns,
            )

        # TODO: Change to ["inspector", "findings"]
        return ["inspector"], get_findings()

    if include_inspector:
        add_task(inspector_describe_findings, "inspector")

    def dynamodb_list_tables() -> Tuple[List[str], Any]:
        log.debug("Executing dynamodb list-tables")
        return ["dynamodb", "TableNames"], paginate(
            "dynamodb", "list_tables", key="TableNames"
        )

    add_task(dynamodb_list_tables, "dynamodb")

    def ecr_describe_repositories() -> Tuple[List[str], Any]:
        log.debug(
            "Executing ecr describe-repositories, get-repository-policy, list-images"
        )

        def get_policy(repository_name: str) -> Dict[str, Any]:
            return json.loads(
                unpaginated(
                    "ecr",
                    "get_repository_policy",
                    param={"repositoryName": repository_name},
                )["policyText"]
            )

        def get_images(repository_name: str) -> List[Dict[str, Any]]:
            return paginate(
                "ecr",
                "list_images",
                key="imageIds",
                param={"repositoryName": repository_name},
            )

        repositories = paginate("ecr", "describe_repositories", key="repositories")
        for repository in repositories:
            repository_name = repository["repositoryName"]
            try:
                repository["policy"] = get_policy(repository_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "RepositoryPolicyNotFoundException":
                    raise
                repository["policy"] = None
            repository["imageIds"] = get_images(repository_name)
        # TODO: Change to ["ecr", "repositories"]
        return ["ecr"], repositories

    add_task(ecr_describe_repositories, "ecr")

    def ecs_describe_clusters() -> Tuple[List[str], Any]:
        log.debug(
            "Executing ecs list-clusters, describe-clusters, list-services, describe-services, list-container-instances, describe-container-instances, list-tasks, describe-tasks"
        )

        def get_cluster_arns() -> List[str]:
            return paginate("ecs", "list_clusters", key="clusterArns")

        def get_clusters() -> List[Dict[str, Any]]:
            cluster_arns = get_cluster_arns()
            return fake_paginate(
                "ecs",
                "describe_clusters",
                request_key="clusters",
                response_key="clusters",
                n=100,
                items=cluster_arns,
                param={"include": ["ATTACHMENTS", "SETTINGS", "STATISTICS", "TAGS"]},
            )

        def get_service_arns(cluster_arn: str) -> List[str]:
            return paginate(
                "ecs",
                "list_services",
                key="serviceArns",
                param={"cluster": cluster_arn},
            )

        def get_services(cluster_arn: str) -> List[Dict[str, Any]]:
            def get_task_arns(service_name: str) -> List[str]:
                return paginate(
                    "ecs",
                    "list_tasks",
                    key="taskArns",
                    param={"cluster": cluster_arn, "serviceName": service_name},
                )

            service_arns = get_service_arns(cluster_arn)
            services = fake_paginate(
                "ecs",
                "describe_services",
                request_key="services",
                response_key="services",
                n=10,
                items=service_arns,
                param={"cluster": cluster_arn},
            )
            for service in services:
                # TODO: Use key "taskArns"
                service["tasks"] = get_task_arns(service["serviceName"])
            return services

        def get_container_instance_arns(cluster_arn: str) -> List[str]:
            return paginate(
                "ecs",
                "list_container_instances",
                key="containerInstanceArns",
                param={"cluster": cluster_arn},
            )

        def get_container_instances(cluster_arn: str) -> List[Dict[str, Any]]:
            def get_task_arns(container_instance_arn: str) -> List[str]:
                return paginate(
                    "ecs",
                    "list_tasks",
                    key="taskArns",
                    param={
                        "cluster": cluster_arn,
                        "containerInstance": container_instance_arn,
                    },
                )

            container_instance_arns = get_container_instance_arns(cluster_arn)
            container_instances = fake_paginate(
                "ecs",
                "describe_container_instances",
                request_key="containerInstances",
                response_key="containerInstances",
                n=100,
                items=container_instance_arns,
                param={"cluster": cluster_arn, "include": ["TAGS"]},
            )
            for container_instance in container_instances:
                # TODO: Use key "taskArns"
                container_instance["tasks"] = get_task_arns(
                    container_instance["containerInstanceArn"]
                )
            return container_instances

        def get_task_arns(cluster_arn: str) -> List[str]:
            return paginate(
                "ecs", "list_tasks", key="taskArns", param={"cluster": cluster_arn}
            )

        def get_tasks(cluster_arn: str) -> List[Dict[str, Any]]:
            task_arns = get_task_arns(cluster_arn)
            return fake_paginate(
                "ecs",
                "describe_tasks",
                request_key="tasks",
                response_key="tasks",
                n=100,
                items=task_arns,
                param={"cluster": cluster_arn, "include": ["TAGS"]},
            )

        clusters = get_clusters()
        for cluster in clusters:
            cluster_arn = cluster["clusterArn"]
            cluster["services"] = get_services(cluster_arn)
            cluster["containerInstances"] = get_container_instances(cluster_arn)
            cluster["tasks"] = get_tasks(cluster_arn)
        # TODO: Change to ["ecs", "clusters"]
        return ["ecs"], clusters

    add_task(ecs_describe_clusters, "ecs")

    def apigateway_get_rest_apis() -> Tuple[List[str], Any]:
        log.debug(
            "Executing apigateway get-rest-apis, get-authorizers, get-deployments, get-request-validators, get-stages, get-resources, get-method"
        )

        def get_authorizers(rest_api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigateway",
                "get_authorizers",
                key="items",
                param={"restApiId": rest_api_id},
            )

        def get_deployments(rest_api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigateway",
                "get_deployments",
                key="items",
                param={"restApiId": rest_api_id},
            )

        def get_request_validators(rest_api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigateway",
                "get_request_validators",
                key="items",
                param={"restApiId": rest_api_id},
            )

        def get_stages(rest_api_id: str) -> List[Dict[str, Any]]:
            return unpaginated(
                "apigateway", "get_stages", param={"restApiId": rest_api_id}
            )["item"]

        def get_resources(rest_api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigateway",
                "get_resources",
                key="items",
                param={"restApiId": rest_api_id},
            )

        def get_method(
            rest_api_id: str, resource_id: str, method: str
        ) -> Dict[str, Any]:
            return unpaginated(
                "apigateway",
                "get_method",
                param={
                    "restApiId": rest_api_id,
                    "resourceId": resource_id,
                    "httpMethod": method,
                },
            )

        rest_apis = paginate("apigateway", "get_rest_apis", key="items")
        for rest_api in rest_apis:
            rest_api_id = rest_api["id"]
            rest_api["authorizers"] = get_authorizers(rest_api_id)
            rest_api["deployments"] = get_deployments(rest_api_id)
            rest_api["requestValidators"] = get_request_validators(rest_api_id)
            rest_api["stages"] = get_stages(rest_api_id)
            rest_api["resources"] = get_resources(rest_api_id)
            for resource in rest_api["resources"]:
                resource["methods"] = []
                for method in resource.get("resourceMethods", []):
                    resource["methods"].append(
                        get_method(rest_api_id, resource["id"], method)
                    )
        # TODO: Change to ["apigateway", "RestApis"]
        return ["apigateway", "Apis"], rest_apis

    add_task(apigateway_get_rest_apis, "apigateway")

    def apigateway_get_usage_plans() -> Tuple[List[str], Any]:
        log.debug("Executing apigateway get-usage-plans, get-usage-plan-keys")

        def get_keys(usage_plan_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigateway",
                "get_usage_plan_keys",
                key="items",
                param={"usagePlanId": usage_plan_id},
            )

        usage_plans = paginate("apigateway", "get_usage_plans", key="items")
        for usage_plan in usage_plans:
            usage_plan["keys"] = get_keys(usage_plan["id"])
        return ["apigateway", "UsagePlans"], usage_plans

    add_task(apigateway_get_usage_plans, "apigateway")

    def apigatewayv2_get_apis() -> Tuple[List[str], Any]:
        log.debug(
            "Executing apigatewayv2 get-apis, get-routes, get-integrations, get-authorizers"
        )

        def get_apis() -> List[Dict[str, Any]]:
            return paginate(
                "apigatewayv2",
                "get_apis",
                key="Items",
            )

        def get_routes(api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigatewayv2",
                "get_routes",
                key="Items",
                param={"ApiId": api_id},
            )

        def get_authorizers(api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigatewayv2",
                "get_authorizers",
                key="Items",
                param={"ApiId": api_id},
            )

        def get_integrations(api_id: str) -> List[Dict[str, Any]]:
            return paginate(
                "apigatewayv2",
                "get_integrations",
                key="Items",
                param={"ApiId": api_id},
            )

        apis = get_apis()
        for api in apis:
            api_id = api["ApiId"]
            api["Routes"] = get_routes(api_id)
            api["Authorizers"] = get_authorizers(api_id)
            api["Integrations"] = get_integrations(api_id)

        return ["apigatewayv2", "Apis"], apis

    add_task(apigatewayv2_get_apis, "apigatewayv2")

    region_data = utils.execute_tasks(tasks, threads)
    if region_data is None:
        raise RuntimeError("utils.execute_tasks returned None")
    return region_data
