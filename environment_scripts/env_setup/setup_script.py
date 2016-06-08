from multiprocessing.pool import ThreadPool
from threading import Lock
from cloudshell.api.cloudshell_api import *
from cloudshell.api.common_cloudshell_api import *
from cloudshell.core.logger import qs_logger
from environment_scripts.helpers.vm_details_helper import get_vm_custom_param

from cloudshell.helpers.scripts import cloudshell_scripts_helpers as helpers
import cloudshell.helpers.scripts.cloudshell_dev_helpers as dev
import os
import time


class EnvironmentSetup(object):
    NO_DRIVER_ERR = "129"
    App_Name = 0
    App_Template = 1
    APP_Configuration_File = 2

    def __init__(self):

        reservation_id = '1c7b4aa4-8397-4be8-be32-359f2bf3af69'
        dev.attach_to_cloudshell_as('admin', 'admin', 'Global', reservation_id, 'localhost', 8029)
        context = os.environ['RESERVATIONCONTEXT']

        self.reservation_id = helpers.get_reservation_context_details().id
        # self.logger = qs_logger.get_qs_logger(name="CloudShell Sandbox Setup", reservation_id=self.reservation_id)
        self.logger = qs_logger.get_qs_logger(log_file_prefix="CloudShell Sandbox Setup",
                                               log_group = self.reservation_id,
                                               log_category = 'Setup')

    def execute(self):
        api = helpers.get_api_session()
        resource_details_cache = {}

        api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message='Beginning reservation setup')
        self._duplicate_non_dc_apps(api)

        #DC
        deploy_result = self._deploy_apps(api, True)
        self._set_OSCustomizationSpec(api, True)
        self._connect_connectors(api, True)
        self._run_async_power_on_refresh_ip_valid_configuration(api, deploy_result, resource_details_cache, True)
        DC_TIMEOUT = time.time() + 60 * 5  # 5 minutes from now
        self._wait_for_all_configuration_files_finish(api, DC_TIMEOUT, True)
        self._run_sanity_tests(api, True)
        self.delete_temp_customization_files(api)

        #Non DC
        deploy_result = self._deploy_apps(api, False)
        self._copy_configuration_file_to_all_non_DC_VMs(api)
        self._set_OSCustomizationSpec(api, False)
        self._connect_connectors(api, False)
        self._run_async_power_on_refresh_ip_valid_configuration(api, deploy_result, resource_details_cache, False)
        TIMEOUT = time.time() + 60 * 7  # 7 minutes from now
        self._wait_for_all_configuration_files_finish(api, TIMEOUT, False)
        self._run_sanity_tests(api, False)







        self.logger.info("Setup for reservation {0} completed".format(self.reservation_id))
        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                            message='Reservation setup finished successfully')




    def _duplicate_non_dc_apps(self, api):

        reservation_details = api.GetReservationDetails(self.reservation_id)

        quantity = 0
        self.apps_templates = []
        non_dc_apps = filter(lambda x: x.LogicalResource.Model != 'DC', reservation_details.ReservationDescription.Apps)
        current_app = [] * 3 # appname/ app Source / configuration file

        for app in non_dc_apps:
            for attribute in app.LogicalResource.Attributes:

                if attribute.Name == 'ConfigurationFileName' and attribute.Value:
                    configutration_file = attribute.Value

                if attribute.Name == 'Quantity':
                    if self._represents_int(attribute.Value):
                        quantity = int(attribute.Value)
                    else: raise ErrorParameter()

                if attribute.Name == 'App Template':
                    app_template = attribute.Value

            if quantity == 1:
                current_app = [app.Name,app.Name, configutration_file]
                self.apps_templates.append(current_app)

            if quantity > 1:
                current_app = [app.Name, app_template, configutration_file] # insert the original app
                self.apps_templates.append(current_app)

                self._duplicate_app(api, app.Name, int(quantity),app_template, configutration_file)
                reservation_details = api.GetReservationDetails(self.reservation_id)
                self._duplicateVLANConnectors(api, app.Name, reservation_details)

            if quantity == 0:
                api.RemoveAppFromReservation(self.reservation_id, app.Name)

    def _represents_int(self, s):
        try:
            int(s)
            return True
        except ValueError:
            return False

    def _duplicate_app(self, api, appname, quantity, app_template, configutration_file):

        _positions = api.GetReservationServicesPositions(self.reservation_id)

        for position in _positions.ResourceDiagramLayouts:
            if position.ResourceName == appname:
                _X = position.X
                _Y = position.Y

        for item in range(0, quantity - 1):
            _X += 20
            _Y += 20
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='Add {0} instance to resevation'.format(appname))
            duplicated_app = api.AddAppToReservation(self.reservation_id, app_template, _X, _Y)
            current_app = [duplicated_app.ReservedAppName, appname, configutration_file]#insert app: new created app/app parent/configuration file
            self.apps_templates.append(current_app)

    def _duplicateVLANConnectors(self, api, appname, reservation_details):

        _connectors = reservation_details.ReservationDescription.Connectors
        for connector in _connectors:
            if connector.Source == appname:
                target = connector.Target
            if connector.Target == appname:
                target = connector.Source
                break

        connectors = []

        for app in reservation_details.ReservationDescription.Apps:
            if appname in app.Name and appname != app.Name:
                connectorRequest = SetConnectorRequest(app.Name, target,'bi','')
                connectors.append(connectorRequest)
                api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                    message='add visual connector between "{0}" and "{1}"'.format(app.Name, target))
        api.SetConnectorsInReservation(self.reservation_id, connectors)

    def _set_OSCustomizationSpec(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        context = ''

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'DC'
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'non DC'

        if not resources:
            return

        if not resources:
            api.WriteMessageToReservationOutput(
                reservationId=self.reservation_id,
                message='No {0} to Set Up OSCustomizationSpec file'.format(context))
            return

        for resource in resources:
            try:
                if is_dc:
                    api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'Set_vm_ip_and_OSCustomizationSpec', False)
                else:
                    api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'Set_OSCustomizationSpec', False)

            except Exception as exc:
                self._internal_error(api, exc.args, exc.message)

    def _connect_connectors(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        context = ''

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC', reservation_details.ReservationDescription.Resources)
            context = 'DC'
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC', reservation_details.ReservationDescription.Resources)
            context = 'non DC'

        if not resources:
            self.logger.info("No {0} to connect, reservation id: {1}: ".format(context, self.reservation_id))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='No {0} to connect'.format(context))
            return

        connectors = reservation_details.ReservationDescription.Connectors
        vlan = ''

        for resource in resources:
            for connector in connectors:
                if connector.Source == resource.Name or connector.Target == resource.Name and connector.State != 'Conected':
                    if connector.Source == resource.Name:
                        vlan = connector.Target
                    if connector.Target == resource.Name:
                        vlan = connector.Source
        if not vlan:
            self.logger.info("No VLANs connected to {0}, reservation id: ".format(resource.Name, self.reservation_id))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='No VLANs connected to {0}'.format(resource.Name))
            return

        self.logger.info("Executing connect VM: {1} routes for reservation {0}".format(self.reservation_id, resource.Name))
        api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message=("Executing connect_all vlan: {0} ".format(vlan)))

        try:
            api.ExecuteCommand(self.reservation_id, vlan, '1', 'Vlan Service Connect All', [], False)
        except CloudShellAPIError as err:
            self._internal_error(err.args, err.message)

    def _connect_non_dc_resources(self, api):
        reservation_details = api.GetReservationDetails(self.reservation_id)
        resources = reservation_details.ReservationDescription.Resources
        resources = filter(lambda x: x.ResourceModelName != 'DC', resources)

        for resource in resources:
            self._connect_connectors(resource.Name, api)

    def _try_exeucte_autoload(self, api, reservation_details, deploy_result, resource_details_cache):
        """
        :param GetReservationDescriptionResponseInfo reservation_details:
        :param CloudShellAPISession api:
        :param BulkAppDeploymentyInfo deploy_result:
        :param (dict of str: ResourceInfo) resource_details_cache:
        :return:
        """

        if deploy_result is None:
            self.logger.info("No apps to discover")
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message='No apps to discover')
            return

        message_written = False

        for deployed_app in deploy_result.ResultItems:
            if not deployed_app.Success:
                continue
            deployed_app_name = deployed_app.AppDeploymentyInfo.LogicalResourceName

            resource_details = api.GetResourceDetails(deployed_app_name)
            resource_details_cache[deployed_app_name] = resource_details

            autoload = "true"
            autoload_param = get_vm_custom_param(resource_details.VmDetails.VmCustomParams, "autoload")
            if autoload_param:
                autoload = autoload_param.Value
            if autoload.lower() != "true":
                self.logger.info("Apps discovery is disabled on deployed app {0}".format(deployed_app_name))
                continue

            try:
                self.logger.info("Executing Autoload command on deployed app {0}".format(deployed_app_name))
                if not message_written:
                    api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                        message='Apps are being discovered...')
                    message_written = True

                api.AutoLoad(deployed_app_name)

            except CloudShellAPIError as exc:
                if exc.code != EnvironmentSetup.NO_DRIVER_ERR:
                    self.logger.error(
                        "Error executing Autoload command on deployed app {0}. Error: {1}".format(deployed_app_name,
                                                                                                  exc.rawxml))
                    api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                        message='Discovery failed on "{0}": {1}'
                                                        .format(deployed_app_name, exc.message))
            except Exception as exc:
                self.logger.error("Error executing Autoload command on deployed app {0}. Error: {1}"
                                  .format(deployed_app_name, str(exc)))
                api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                    message='Discovery failed on "{0}": {1}'
                                                    .format(deployed_app_name, exc.message))

    def _deploy_apps_in_reservation(self, api, reservation_details):
        apps = reservation_details.ReservationDescription.Apps
        if not apps or (len(apps) == 1 and not apps[0].Name):
            self.logger.info("No apps found in reservation {0}".format(self.reservation_id))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='No apps to deploy')
            return None

        app_names = map(lambda x: x.Name, apps)
        app_inputs = map(lambda x: DeployAppInput(x.Name, "Name", x.Name), apps)

        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                            message='Apps deployment started')
        self.logger.info(
            "Deploying apps for reservation {0}. App names: {1}".format(reservation_details, ", ".join(app_names)))

        res = api.DeployAppToCloudProviderBulk(self.reservation_id, app_names, app_inputs)

        return res

    def _deploy_apps(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        all_apps = reservation_details.ReservationDescription.Apps
        context = ''

        if is_dc:
            apps = filter(lambda x: x.LogicalResource.Model == 'DC', all_apps)
            context = 'DC'

        else:
            apps = filter(lambda x: x.LogicalResource.Model != 'DC', all_apps)
            context = 'Non DC'

        if not apps or (len(apps) == 0):
            self.logger.info("No '{1}' apps found in reservation {0}".format(self.reservation_id, context))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message="No '{1}' apps found in reservation {0}".format(self.reservation_id, context))
            return None

        app_names = map(lambda x: x.Name, apps)
        app_inputs = map(lambda x: DeployAppInput(x.Name, "Name", x.Name), apps)

        api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message="Start deploy {0} apps".format(context))
        self.logger.info("Start deploy {0} apps".format(context))

        res = api.DeployAppToCloudProviderBulk(self.reservation_id, app_names, app_inputs)

        for item in res.ResultItems:
            if not item.Success:
                self._internal_error('Fail to deploy VM', item.AppName)

        return res

    def _copy_configuration_file_to_all_non_DC_VMs(self, api):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        non_dc_resources = filter(lambda x: x.ResourceModelName != 'DC', reservation_details.ReservationDescription.Resources)

        for resource in non_dc_resources:
            for app in self.apps_templates:
                    underscore_position = int(resource.Name.rfind('_'))
                    origin_app_name = resource.Name[0:underscore_position]

                    if app[self.App_Name] == origin_app_name:
                        api.SetAttributeValue(resource.Name, 'ConfigurationFileName', app[self.APP_Configuration_File])

    def _connect_all_routes_in_reservation(self, api, reservation_details):
        connectors = reservation_details.ReservationDescription.Connectors
        endpoints = []
        for endpoint in connectors:
            if endpoint.State in ['Disconnected', 'PartiallyConnected', 'ConnectionFailed'] \
                    and endpoint.Target and endpoint.Source:
                endpoints.append(endpoint.Target)
                endpoints.append(endpoint.Source)

        if not endpoints:
            self.logger.info("No routes to connect for reservation {0}".format(self.reservation_id))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='Nothing to connect')
            return

        self.logger.info("Executing connect routes for reservation {0}".format(self.reservation_id))
        self.logger.debug("Connecting: {0}".format(",".join(endpoints)))
        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                            message='Connecting all apps')
        res = api.ConnectRoutesInReservation(self.reservation_id, endpoints, 'bi')
        return res

    def _run_async_power_on_refresh_ip_valid_configuration(self, api, deploy_results, resource_details_cache, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        context = ''

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'DC'
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'non DC'

        if not resources:
            self.logger.info("No {0} to power on, reservation id: {1}: ".format(context, self.reservation_id))
            api.WriteMessageToReservationOutput( reservationId=self.reservation_id,message='No {0} to power on or install'.format(context))
            #self._validate_all_apps_deployed(deploy_results)
            return

        pool = ThreadPool(len(resources))
        lock = Lock()
        message_status = {
            "power_on": False,
            "wait_for_ip": False,
            "install": False
        }

        async_results = [pool.apply_async(self._power_on_refresh_ip_install,
                                          (api, lock, message_status, resource, deploy_results, resource_details_cache))
                         for resource in resources]

        pool.close()
        pool.join()

        for async_result in async_results:
            res = async_result.get()
            if not res[0]:
                raise Exception("Reservation is Active with Errors - " + res[1])

                # self._validate_all_apps_deployed(deploy_results)

    def _run_non_dc_sanity_tests(self, api, reservation_details, timeout):

        resources = filter(lambda x: x.ResourceModelName != 'DC', reservation_details.ReservationDescription.Resources)

        configuration_done = [0] * len(resources)
        condition = any(item != 1 for item in configuration_done)

        while condition:

            for index, dc in enumerate(resources):
                res = api.ExecuteCommand(self.reservation_id, dc.Name, '0', 'DC_customization_finished', [dc.FullAddress], False)

                if res.Output == '1':
                    configuration_done[index] = 1
                    self.logger.debug("DC: {0} - finish customiztion file deployment".format(dc.Name))
                    api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                        message=("DC: {0} - finish customiztion file deployment".format(dc.Name)))

                    condition = any(item != 1 for item in configuration_done)
                    if not condition:
                        break

                if 0 in configuration_done and time.time() > timeout:
                    y = next(i for i, v in enumerate(configuration_done) if v != 0)
                    errored_dc = configuration_done[y]
                    raise Exception("Timeout-DC: DC:{0} fail to spinup after timeput:{1} seconds.".format(errored_dc, timeout/60))
        return

    def _wait_for_all_configuration_files_finish(self, api, timeout, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        context = ''

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'DC'
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'non DC'

        if not resources:
            return

        configuration_done = [0] * len(resources)
        condition = any(item != 1 for item in configuration_done)

        while condition:

            for index, dc in enumerate(resources):
                res = api.ExecuteCommand(self.reservation_id, dc.Name, '0', 'Customization_finished',
                                         [dc.FullAddress], False)

                if res.Output == '1':
                    configuration_done[index] = 1
                    self.logger.debug("DC: {0} - finish customiztion file deployment".format(dc.Name))
                    api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                        message=("DC: {0} - finish customiztion file deployment".format(
                                                            dc.Name)))

                    condition = any(item != 1 for item in configuration_done)
                    if not condition:
                        break

                if 0 in configuration_done and time.time() > timeout:
                    y = next(i for i, v in enumerate(configuration_done) if v != 0)
                    errored_dc = configuration_done[y]
                    raise Exception(
                        "Timeout-DC: DC:{0} fail to spinup after timeput:{1} seconds.".format(errored_dc, timeout / 60))
        return

    def _run_sanity_tests(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        context = ''

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'DC'
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'non DC'

        if not resources:
            return

        for resource in resources:
            try:
                if resource.ResourceModelName == 'DC':
                    res = api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'DC_sanity_test',
                                             [resource.FullAddress], False)
                if resource.ResourceModelName == 'WS':
                    res = api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'WS_sanity_test',
                                             [resource.FullAddress], False)

            except Exception as exc:
                self._internal_error(api, exc.args, exc.message)

            if res.Output == '1':
                self.logger.debug("VM: {0} - Sanity test passed".format(resource.Name))
                api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message=("VM: {0} - Sanity test passed".format(resource.Name)))
            else:
                self.logger.debug("Error: VM: {0} - Sanity test fail".format(resource.Name))
                api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message=("Error: VM: {0} - Sanity test passed".format(resource.Name)))

    def delete_temp_customization_files(self, api):

        reservation_details = api.GetReservationDetails(self.reservation_id)

        DCs = filter(lambda x: x.ResourceModelName == 'DC', reservation_details.ReservationDescription.Resources)

        for dc in DCs:
            try:
                api.ExecuteCommand(self.reservation_id, dc.Name, '0', 'Delete_OSCustomizationSpec', [dc.FullAddress], False)
            except Exception as exc:
                self._internal_error(api, exc.args, exc.message)

    def _run_async_power_on_refresh_ip_install(self, api, reservation_details, deploy_results, resource_details_cache):
        """
        :param CloudShellAPISession api:
        :param GetReservationDescriptionResponseInfo reservation_details:
        :param BulkAppDeploymentyInfo deploy_results:
        :param (dict of str: ResourceInfo) resource_details_cache:
        :return:
        """
        resources = reservation_details.ReservationDescription.Resources
        if len(resources) == 0:
            api.WriteMessageToReservationOutput(
                reservationId=self.reservation_id,
                message='No resources to power on or install')
            self._validate_all_apps_deployed(deploy_results)
            return

        pool = ThreadPool(len(resources))
        lock = Lock()
        message_status = {
            "power_on": False,
            "wait_for_ip": False,
            "install": False
        }

        async_results = [pool.apply_async(self._power_on_refresh_ip_install,
                                          (api, lock, message_status, resource, deploy_results, resource_details_cache))
                         for resource in resources]

        pool.close()
        pool.join()

        for async_result in async_results:
            res = async_result.get()
            if not res[0]:
                raise Exception("Reservation is Active with Errors - " + res[1])

        self._validate_all_apps_deployed(deploy_results)

    def _validate_all_apps_deployed(self, deploy_results):
        if deploy_results is not None:
            for deploy_res in deploy_results.ResultItems:
                if not deploy_res.Success:
                    raise Exception("Reservation is Active with Errors - " + deploy_res.Error)

    def _power_on_refresh_ip_install(self, api, lock, message_status, resource, deploy_result, resource_details_cache):
        """
        :param CloudShellAPISession api:
        :param Lock lock:
        :param (dict of str: Boolean) message_status:
        :param ReservedResourceInfo resource:
        :param BulkAppDeploymentyInfo deploy_result:
        :param (dict of str: ResourceInfo) resource_details_cache:
        :return:
        """

        deployed_app_name = resource.Name
        deployed_app_data = None

        power_on = "true"
        wait_for_ip = "true"

        try:
            self.logger.debug("Getting resource details for resource {0} in reservation {1}"
                              .format(deployed_app_name, self.reservation_id))

            if deployed_app_name in resource_details_cache:
                resource_details = resource_details_cache[deployed_app_name]
            else:
                resource_details = api.GetResourceDetails(deployed_app_name)

            # check if deployed app
            if not hasattr(resource_details.VmDetails, "UID"):
                self.logger.debug("Resource {0} is not a deployed app, nothing to do with it".format(deployed_app_name))
                return True, ""

            auto_power_on_param = get_vm_custom_param(resource_details.VmDetails.VmCustomParams, "auto_power_on")
            if auto_power_on_param:
                power_on = auto_power_on_param.Value
            wait_for_ip_param = get_vm_custom_param(resource_details.VmDetails.VmCustomParams, "wait_for_ip")
            if wait_for_ip_param:
                wait_for_ip = wait_for_ip_param.Value

            # check if we have deployment data
            if deploy_result is not None:
                for data in deploy_result.ResultItems:
                    if data.Success and data.AppDeploymentyInfo.LogicalResourceName == deployed_app_name:
                        deployed_app_data = data
        except Exception as exc:
            self.logger.error("Error getting resource details for deployed app {0} in reservation {1}. "
                              "Will use default settings. Error: {2}".format(deployed_app_name,
                                                                             self.reservation_id,
                                                                             str(exc)))

        try:
            self._power_on(api, deployed_app_name, power_on, lock, message_status)
        except Exception as exc:
            self.logger.error("Error powering on deployed app {0} in reservation {1}. Error: {2}"
                              .format(deployed_app_name, self.reservation_id, str(exc)))
            return False, "Error powering on deployed app {0}".format(deployed_app_name)

        try:
            self._wait_for_ip(api, deployed_app_name, wait_for_ip, lock, message_status)
        except Exception as exc:
            self.logger.error("Error refreshing IP on deployed app {0} in reservation {1}. Error: {2}"
                              .format(deployed_app_name, self.reservation_id, str(exc)))
            return False, "Error refreshing IP deployed app {0}. Error: {1}".format(deployed_app_name, exc.message)

        try:
            self._install(api, deployed_app_data, deployed_app_name, lock, message_status)
        except Exception as exc:
            self.logger.error("Error installing deployed app {0} in reservation {1}. Error: {2}"
                              .format(deployed_app_name, self.reservation_id, str(exc)))
            return False, "Error installing deployed app {0}. Error: {1}".format(deployed_app_name, str(exc))

        return True, ""

    def _install(self, api, deployed_app_data, deployed_app_name, lock, message_status):
        installation_info = None
        if deployed_app_data:
            installation_info = deployed_app_data.AppInstallationInfo
        else:
            self.logger.info("Cant execute installation script for deployed app {0} - No deployment data"
                             .format(deployed_app_name))
            return

        if installation_info and hasattr(installation_info, "ScriptCommandName"):
            self.logger.info("Executing installation script {0} on deployed app {1} in reservation {2}"
                             .format(installation_info.ScriptCommandName, deployed_app_name, self.reservation_id))

            if not message_status['install']:
                with lock:
                    if not message_status['install']:
                        message_status['install'] = True
                        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                            message='Apps are installing...')

            script_inputs = []
            for installation_script_input in installation_info.ScriptInputs:
                script_inputs.append(
                    InputNameValue(installation_script_input.Name, installation_script_input.Value))

            installation_result = api.InstallApp(self.reservation_id, deployed_app_name,
                                                 installation_info.ScriptCommandName, script_inputs)

            self.logger.debug("Installation_result: " + installation_result.Output)

    def _wait_for_ip(self, api, deployed_app_name, wait_for_ip, lock, message_status):
        if wait_for_ip.lower() == "true":

            if not message_status['wait_for_ip']:
                with lock:
                    if not message_status['wait_for_ip']:
                        message_status['wait_for_ip'] = True
                        api.WriteMessageToReservationOutput(
                            reservationId=self.reservation_id,
                            message='Waiting for apps IP addresses, this may take a while...')

            self.logger.info("Executing 'Refresh IP' on deployed app {0} in reservation {1}"
                             .format(deployed_app_name, self.reservation_id))

            api.ExecuteResourceConnectedCommand(self.reservation_id, deployed_app_name,
                                                "remote_refresh_ip",
                                                "remote_connectivity")
        else:
            self.logger.info("Wait For IP is off for deployed app {0} in reservation {1}"
                             .format(deployed_app_name, self.reservation_id))

    def _power_on(self, api, deployed_app_name, power_on, lock, message_status):
        if power_on.lower() == "true":
            self.logger.info("Executing 'Power On' on deployed app {0} in reservation {1}"
                             .format(deployed_app_name, self.reservation_id))

            if not message_status['power_on']:
                with lock:
                    if not message_status['power_on']:
                        message_status['power_on'] = True
                        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                            message='Apps are powering on...')

            api.ExecuteResourceConnectedCommand(self.reservation_id, deployed_app_name, "PowerOn", "power")
        else:
            self.logger.info("Auto Power On is off for deployed app {0} in reservation {1}"
                             .format(deployed_app_name, self.reservation_id))

    def _internal_error(self, api, str_args, message):
        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                            message=("ERROR: {0} \n {1}".format(message,str_args)))