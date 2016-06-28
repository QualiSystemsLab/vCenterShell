from multiprocessing.pool import ThreadPool
from threading import Lock
from cloudshell.api.cloudshell_api import *
from cloudshell.api.common_cloudshell_api import *
from cloudshell.core.logger import qs_logger, interprocess_logger
from environment_scripts.helpers.vm_details_helper import get_vm_custom_param
from utility import ProcessRunner
import regex as re

from cloudshell.helpers.scripts import cloudshell_scripts_helpers as helpers
import cloudshell.helpers.scripts.cloudshell_dev_helpers as dev
import os
import time


class EnvironmentSetup(object):
    DC_TIMEOUT = time.time() + 60 * 0.3  # 15 minutes from now
    NON_DC_TIMEOUT = time.time() + 60 * 7  # 7 minutes from now

    NO_DRIVER_ERR = "129"
    App_Name = 0
    APP_Parent = 1
    App_Template = 2
    APP_Configuration_File = 3
    Configuration_Done = 'EndCustomization'
    Stop_Deployment_code = '201'
    Throw_Error_And_Continue_Code = '202'

    # vm state
    Deployed = '0_Deployed'
    File_Associated = '1_FileAssociated'
    Connected = '2_Connected'
    Powered_On = '3_PowerdOn'
    Customized = '4_Customized'
    SanityPass = '5_SanityPass'

    sandbox_apps = []  # app name/ app parent/ app template /configuration file

    def __init__(self):

        #reservation_id = '6c470fd0-723e-4b46-aff2-b0a8c1f07ab6'
        #dev.attach_to_cloudshell_as('admin', 'admin', 'Global', reservation_id, 'localhost', 8029)
        context = os.environ['RESERVATIONCONTEXT']

        self.reservation_id = helpers.get_reservation_context_details().id
        self.logger = qs_logger.get_qs_logger(name="CloudShell Sandbox Setup", reservation_id=self.reservation_id)
        self.logger = qs_logger.get_qs_logger(log_file_prefix="CloudShell Sandbox Setup",
                                              log_group=self.reservation_id,
                                              log_category='Setup')

    def execute(self):
        api = helpers.get_api_session()
        resource_details_cache = {}

        api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message='Beginning Sandbox setup\n')
        self._duplicate_non_dc_apps(api)

        # DC
        deploy_result = self._deploy_apps(api, True)
        self._set_os_customization_spec(api, True)
        self._connect_connectors(api, True)
        self._run_async_power_on_refresh_ip_valid_configuration(api, deploy_result, resource_details_cache, True)
        self._wait_for_all_configuration_files_finish(api, self.DC_TIMEOUT, True)
        self._run_sanity_tests(api, True)
        self.delete_temp_customization_files(api)

        #  Non DC
        deploy_result = self._deploy_apps(api, False)
        self._copy_configuration_file_to_all_non_dc_vms(api)
        self._set_os_customization_spec(api, False)
        self._connect_connectors(api, False)
        self._run_async_power_on_refresh_ip_valid_configuration(api, deploy_result, resource_details_cache, False)
        self._wait_for_all_configuration_files_finish(api, self.NON_DC_TIMEOUT, False)
        self._run_sanity_tests(api, False)

        self.logger.info("Setup for reservation {0} completed".format(self.reservation_id))
        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                            message='Reservation setup finished successfully')

    @staticmethod
    def _represents_int(s):
        try:
            int(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _get_resource_base_state(api, resource_list, state):
        resources = []
        attribute_name = 'VM State'

        for resource in resource_list:
            resource_state = api.GetAttributeValue(resource.Name, attribute_name)
            if resource_state.Value == state:
                resources.append(resource)

        return resources

    @staticmethod
    def is_ipv4(ip):
        match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
        if not match:
            return False
        quad = []
        for number in match.groups():
            quad.append(int(number))
        if quad[0] < 1:
            return False
        for number in quad:
            if number > 255 or number < 0:
                return False
        return True

    def _set_resource_base_state(self, api, resource_list, state):
        attribute_name = 'VM State'

        for resource in resource_list:
            if state == self.Deployed:  # this list is simple list on list of an objects
                api.SetAttributeValue(resource, attribute_name, state)
            else:
                api.SetAttributeValue(resource.Name, attribute_name, state)

    def _duplicate_non_dc_apps(self, api):

        reservation_details = api.GetReservationDetails(self.reservation_id)

        quantity = 0
        non_dc_apps = filter(lambda x: x.LogicalResource.Model != 'DC', reservation_details.ReservationDescription.Apps)

        for app in non_dc_apps:
            for attribute in app.LogicalResource.Attributes:

                if attribute.Name == 'ConfigurationFileName' and attribute.Value:
                    configuration_file = attribute.Value

                if attribute.Name == 'Quantity':
                    if self._represents_int(attribute.Value):
                        quantity = int(attribute.Value)
                    else:
                        raise ErrorParameter()

                if attribute.Name == 'App Template':
                    app_template = attribute.Value

            if quantity == 1:
                current_app = [app.Name,'', app.Name, configuration_file]
                self.sandbox_apps.append(current_app)

            if quantity > 1:
                current_app = [app.Name,'', app_template, configuration_file]  # insert the first app to the container
                self.sandbox_apps.append(current_app)

                self._duplicate_app(api, app.Name, int(quantity), app_template, configuration_file)
                reservation_details = api.GetReservationDetails(self.reservation_id)
                self._duplicate_vlan_connectors(api, app.Name, reservation_details)

            if quantity == 0:
                api.RemoveAppFromReservation(self.reservation_id, app.Name)

    def _duplicate_app(self, api, app_to_duplicate, quantity, app_template, configuration_file):

        _positions = api.GetReservationServicesPositions(self.reservation_id)

        for position in _positions.ResourceDiagramLayouts:
            if position.ResourceName == app_to_duplicate:
                _X = position.X
                _Y = position.Y

        for item in range(0, quantity - 1):
            _X += 20
            _Y += 20
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='Add {0} instance to reservation'.format(app_to_duplicate))
            duplicated_app = api.AddAppToReservation(self.reservation_id, app_template, _X, _Y)
            #  insert app: new created app/app parent/configuration file
            current_app = [duplicated_app.ReservedAppName, app_to_duplicate, app_template , configuration_file]
            self.sandbox_apps.append(current_app)

    def _set_duplicate_apps_names(self, api, resources):

        for app in self.sandbox_apps:
                for index, resource in enumerate(resources):
                    underscore_position = int(resource.rfind('_'))
                    origin_app_name = resource[0:underscore_position]

                    if origin_app_name == app[self.App_Name] and app[self.APP_Parent] != '':  # not root app
                        suffix = resource[underscore_position:len(resource)]
                        new_name = app[self.APP_Parent] + str(index) + suffix

                        api.RenameResource(resource, new_name)

    def _duplicate_vlan_connectors(self, api, parent_app, reservation_details):

        _connectors = reservation_details.ReservationDescription.Connectors

        target=''
        for connector in _connectors:
            if connector.Source == parent_app:
                target = connector.Target
            if connector.Target == parent_app:
                target = connector.Source
                break

        # one of hte apps has no VLAN
        if not target:
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message="'{0} has no VLAN connection".format(parent_app))
            self._internal_error(api, '20129', "'{0} has no VLAN connection".format(parent_app))

        connectors = []

        #Get all the apps which share the same app_parent
        for app_instance in self.sandbox_apps:
            if app_instance[self.APP_Parent] == parent_app:
                request = SetConnectorRequest(app_instance[self.App_Name], target, 'bi', '')
                connectors.append(request)
                api.SetConnectorsInReservation(self.reservation_id, connectors)

                api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                    message='add visual connector between "{0}" and "{1}"'.format(app_instance[self.App_Name], target))

    def _set_os_customization_spec(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'DC'
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)
            context = 'non DC'

        resources = self._get_resource_base_state(api, resources, self.Deployed)  # only deployed resources

        if not resources:
            api.WriteMessageToReservationOutput(
                reservationId=self.reservation_id,
                message='No {0} to Set Up OSCustomizationSpec file'.format(context))
            return

        for resource in resources:
            try:
                if is_dc:
                    api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'Set_vm_ip_and_OSCustomizationSpec',[], False)
                else:
                   api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'Set_OSCustomizationSpec', [], False)

            except Exception as exc:
                if is_dc:
                    self._internal_error(api, '20134', exc.message, str_args=exc.args)
                else:
                    self._internal_error(api, '20231', exc.message, str_args=exc.args)

        #  set resources state
        self._set_resource_base_state(api, resources, self.File_Associated)

    def _connect_connectors(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC', reservation_details.ReservationDescription.
                               Resources)
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC', reservation_details.ReservationDescription.
                               Resources)

        # only resources with customization file
        resources = self._get_resource_base_state(api, resources, self.File_Associated)

        if not resources:
            return

        connectors = reservation_details.ReservationDescription.Connectors
        vlan = ''

        for resource in resources:
            for connector in connectors:
                if connector.Source == resource.Name or connector.Target == resource.Name:
                    if connector.Source == resource.Name:
                        vlan = connector.Target
                    if connector.Target == resource.Name:
                        vlan = connector.Source

            if not vlan:
                self.logger.info("No VLANs connected to {0}: ".format(resource.Name, self.reservation_id))
                api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                    message='No VLANs connected to {0}'.format(resource.Name))
                self._internal_error(api, '20129', message="No VLANs connected to '{0}'".format(resource.Name))

            else:
                if connector.State != 'Connected':
                    self.logger.info("Executing connect VLAN: '{1}' routes".format(self.reservation_id, vlan))
                    api.WriteMessageToReservationOutput(reservationId=self.reservation_id,message=("Executing connect"
                                                       "VLAN: '{1}' ""routes".format(self.reservation_id, vlan)))

                    try:
                        api.ExecuteCommand(self.reservation_id, vlan, '1', 'Vlan Service Connect All', [], False)
                    except CloudShellAPIError as err:
                        if is_dc:
                            self._internal_error(api, '20135', "Fail connect 'DC' VM to VLAN, " + err.message, err.args)
                        else:
                            self._internal_error(api, '20132', "Fail connect 'non DC' VM to VLAN, " + err.message, err.args)

        #  set resources state
        self._set_resource_base_state(api, resources, self.Connected)

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

        if is_dc:
            apps = filter(lambda x: x.LogicalResource.Model == 'DC', all_apps)
            context = 'DC'

        else:
            apps = filter(lambda x: x.LogicalResource.Model != 'DC', all_apps)
            context = 'Non DC'

        if not apps or (len(apps) == 0):
            self.logger.info("No '{1}' apps found in reservation {0}".format(self.reservation_id, context))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message="No '{1}' apps found in reservation {0}".format(
                                                    self.reservation_id, context))
            if is_dc:
                self._internal_error(api, '20130', "No 'DC' apps found in Sandbox")
            else:
                self._internal_error(api, '20132', "No 'Non DC' apps found in Sandbox")

        app_names = map(lambda x: x.Name, apps)
        app_inputs = map(lambda x: DeployAppInput(x.Name, "Name", x.Name), apps)

        api.WriteMessageToReservationOutput(self.reservation_id, message="Start deploy {0} apps".format(context))
        self.logger.info("Start deploy {0} apps".format(context))

        res = api.DeployAppToCloudProviderBulk(self.reservation_id, app_names, app_inputs)

        for item in res.ResultItems:
            if not item.Success:
                for x in range(2):  # try 2 more times
                    api.WriteMessageToReservationOutput(self.reservation_id,
                                                        message="{0} deployment fail, try deploy again".format(item.AppName))

                    res = api.DeployAppToCloudProviderBulk(self.reservation_id, app_names, app_inputs)

                    if all(item.Success for item in res.ResultItems):
                        api.WriteMessageToReservationOutput(self.reservation_id,
                                                            message="Finish deploy {0} successfully".format(context))
                        self.logger.info("Finish deploy {0} successfully".format(context))
                        return

                # fail after retry
                if is_dc:
                    self._internal_error(api, '20131', message='Fail to deploy DC: {0}'.format(item.AppName),
                                         str_args=item.Error )
                else:
                    self._internal_error(api, '20133', message='Fail to deploy DC: {0}'.format(item.AppName),
                                         str_args=item.Error )

            api.WriteMessageToReservationOutput(self.reservation_id,
                                                message="Finish deploy {0} successfully".format(context))

            deployed_resources = []

            for deployed_item in res.ResultItems:
                deployed_resources.append(deployed_item.AppDeploymentyInfo.LogicalResourceName)

            #  set resource status
            self._set_resource_base_state(api, deployed_resources, self.Deployed)

            #  Set correct name for non dc
            #if not is_dc:
            #   self._set_duplicate_apps_names(api, deployed_resources)

            self.logger.info("Finish deploy {0} successfully".format(context))
            return res

    def _copy_configuration_file_to_all_non_dc_vms(self, api):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        non_dc_resources = filter(lambda x: x.ResourceModelName != 'DC', reservation_details.ReservationDescription.Resources)

        for resource in non_dc_resources:
            for app in self.sandbox_apps:
                    underscore_position = int(resource.Name.rfind('_'))
                    origin_app_name = resource.Name[0:underscore_position]

                    try:
                        if app[self.App_Name] == origin_app_name:
                            api.SetAttributeValue(resource.Name, 'ConfigurationFileName',
                                                  app[self.APP_Configuration_File])
                    except Exception as exc:
                            self._internal_error(api, '20230', exc.message, exc.message)

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
        self._validate_all_apps_deployed(deploy_results)

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)

        # only resources with customization file
        resources = self._get_resource_base_state(api, resources, self.Connected)  # only deployed resources

        if not resources:

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
                if is_dc:
                    self._internal_error(api, '20136', 'Fail power on DC',res[1])
                else:
                    self._internal_error(api, '20233', 'Fail power on non DC vm', res[1])

        #  set resources state
        self._set_resource_base_state(api, resources, self.Powered_On)

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
        process_runner = ProcessRunner()
        dc_input_ips = []

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)

        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)

        resources = self._get_resource_base_state(api, resources, self.Powered_On)  # only powered on resources

        #  Get the user input IPs
        if is_dc:
            for resource in resources:
                dc_input_ips.append(api.GetAttributeValue(resource.Name,'IP').Value)

        configuration_done = [0] * len(resources)
        not_all_vms_finish_customization = any(item == 0 for item in configuration_done)

        while not_all_vms_finish_customization:
            for index, vm in enumerate(resources):
                api.ExecuteResourceConnectedCommand(self.reservation_id, vm.Name,
                                                    "remote_refresh_ip",
                                                    "remote_connectivity")  # refresh ip in cs from the resource

                current_vm_ip = vm.FullAddress
                if is_dc:
                    if current_vm_ip not in dc_input_ips:
                        time.sleep(5)
                        break  # end of  for index, vm in enumerate(resources) loop
                else:
                    if not self.is_ipv4(current_vm_ip):
                        time.sleep(5)
                        break  # end of  for index, vm in enumerate(resources) loop

                command = 'cmdkey /add:__IP__ /user:__USER__ /pass:__PASSWORD__'

                ip = resources[index].FullAddress
                user = 'administrator'
                password = 'Welcome1!'
                command = command.replace('__USER__', user)
                command = command.replace('__PASSWORD__', password)

                res = process_runner.execute(command, None)  # set command credentials
                if 'Credential added successfully' not in res[0]:
                    api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                        message=("CloudShell Execution server fail access VM: '{0}'".
                                                                 format(ip)))
                    self._internal_error(api,'20137', "CloudShell Execution server fail access VM: '{0}'".format(ip))

                if configuration_done[index] == 0:
                    cmd_dir = 'dir \\\\{0}\\c$ /A:D'.format(ip)

                    result = []
                    try:
                        result = process_runner.execute(cmd_dir, None)
                    except:
                        None

                    if self.Configuration_Done in result[0]:
                        configuration_done[index] = 1
                        self.logger.debug("VM: {0} - finish customiztion file deployment".format(vm.Name))
                        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                            message=("VM: {0} - finish customiztion file deploymen"
                                                                     "t".format(vm.Name)))

            if 0 in configuration_done and time.time() > timeout:

                errored_vm = ''
                errored_vm_address = ''

                for index, val in enumerate(configuration_done):
                    if val == 0:
                        errored_vm = resources[index].Name
                        errored_vm_address = resources[index].FullAddress
                        break

                if is_dc:
                    message = ("Timeout:DC -  fail to find customization finish key in vm {0}, vm ip:{1} ".format(
                        errored_vm, errored_vm_address))
                    key = '20138'
                else:
                    message = ("Timeout:non DC -fail to find customization finish key in vm {0}, vm ip:{1} ".format(
                        errored_vm, errored_vm_address))
                    key = '20233'

                api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message= message)
                self._internal_error(api, key, message)
                return  # for non dc only

            not_all_vms_finish_customization = any(item == 0 for item in configuration_done)

            time.sleep(30)

        # out of While
        if is_dc:
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='All DC VMs finished deployment')
        else:
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message='All not DC VMs finished deployment')

        #  set resources state
        self._set_resource_base_state(api, resources, self.Configuration_Done)

    def _run_sanity_tests(self, api, is_dc):

        reservation_details = api.GetReservationDetails(self.reservation_id)
        res = None

        if is_dc:
            resources = filter(lambda x: x.ResourceModelName == 'DC',
                               reservation_details.ReservationDescription.Resources)
        else:
            resources = filter(lambda x: x.ResourceModelName != 'DC',
                               reservation_details.ReservationDescription.Resources)

        resources = self._get_resource_base_state(api, resources, self.Customized)  # only customized resources

        if not resources:
            return

        for resource in resources:
            try:
                res = api.ExecuteCommand(self.reservation_id, resource.Name, '0', 'Sanity_test_main',
                                             [resource.FullAddress], False)

            except Exception as exc:
                if is_dc:
                    self._internal_error(api, '20234','DC sanity test error' + exc.message, exc.args)
                else:
                    self._internal_error(api, '20235', 'Non DC sanity test error' + exc.message, exc.args)

            if res.Output == '1':
                self.logger.debug("VM: {0} - Sanity test passed".format(resource.Name))
                api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message=("VM: {0} - Sanity test"
                                                                                                " passed".format
                                                                                                (resource.Name)))
            else:
                if is_dc:
                    res2 = "DC: {0} sanity test end with failure".format(resource.Name)
                    key = '20236'
                else:
                    res2 = "non DC: {0} sanity test end with failure".format(resource.Name)
                    key = '20237'

                api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message=res2)
                self._internal_error(api, key, res2, str_args=res.Output)

        #  set resources state
        self._set_resource_base_state(api, resources, self.SanityPass)

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
                    self._internal_error("Reservation is Active with Errors - " + deploy_res.Error)

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

    def _internal_error(self, api, error_id, message, str_args=None):

        args = 'ErrorID=' + error_id

        if str_args:
            args += '. ' + str_args

        api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                            message=("\nERROR:\n"
                                                     "Massage: {0} \n"
                                                     "Args: {1}\n\n"
                                                     .format(message, args)))

        if error_id.startswith(self.Stop_Deployment_code):
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id, message='End Deployment')
            self._clean_sandbox(api)
            raise Exception(message, args)  # CCT Error EXE placed here

        if error_id.startswith(self.Throw_Error_And_Continue_Code):
            None

    def _clean_sandbox(self,api):

        reservation_details = api.GetReservationDetails(self.reservation_id)

        for resource in reservation_details.ReservationDescription.Resources:
            res = api.ExecuteResourceConnectedCommand(self.reservation_id, resource.Name, 'destroy_vm','app_management', [], [], True)

            self.logger.debug("Delete VM:{0}".format(resource.Name))
            api.WriteMessageToReservationOutput(reservationId=self.reservation_id,
                                                message=("Delete VM:{0}".format(resource.Name)))