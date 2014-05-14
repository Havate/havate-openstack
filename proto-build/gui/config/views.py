import os
import subprocess
import yaml

from django.views.generic import View
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.core.urlresolvers import reverse
from django.core import serializers
from django.conf import settings
from django.template.loader import render_to_string

from braces.views import JSONResponseMixin, AjaxResponseMixin

from config.forms import ClusterSettingsForm, UCSMSettingsForm, OSSettingsForm, HostSettingsForm, NodeSettingsForm, NetworkSettingsForm, OpenstackSettingsForm
from config.models import OpenstackSettings, NodeSettings
from config.helpers import construct_conf_file

def traverse_tree(dictionary):
    try:
        for key, value in dictionary.items():
            if value == None:
                dictionary[key] = u""
            traverse_tree(value)
    except Exception, e:
        pass
    return

class HomePageView(TemplateView):

    template_name = "home.html"

class SettingsTextView(TemplateView):

    template_name = "config.template"

    def get_context_data(self, **kwargs):
        context = super(SettingsTextView, self).get_context_data(**kwargs)
        try:
            context['nodes'] = serializers.serialize('python', NodeSettings.objects.all())
            context['settings'] = serializers.serialize('python', OpenstackSettings.objects.all())
        except IndexError:
            pass
        return context

class SettingsView(TemplateView):

    template_name = "new_template.html"

    def get_context_data(self, **kwargs):
        context = super(SettingsView, self).get_context_data(**kwargs)
        context['cluster_form'] = ClusterSettingsForm()
        context['ucsm_form'] = UCSMSettingsForm()
        context['os_form'] = OSSettingsForm()
        context['network_form'] = NetworkSettingsForm
        context['host_form'] = HostSettingsForm()
        context['node_form'] = NodeSettingsForm()
        context['settings_form'] = OpenstackSettingsForm()
        context['nodes'] = NodeSettings.objects.all()
        context['settings'] = {}
        try:
            context['settings'] = OpenstackSettings.objects.all()[0]
            context['settings_form'] = OpenstackSettingsForm(instance=context['settings'])
        except IndexError:
            pass
        scenario_list = []
        for filename in os.listdir(os.path.join(settings.PROJECT_PATH, 'static-raw', 'scenarios')):
            if filename.endswith(".yaml"):
                scenario_list.append(filename.split('.')[0])
        context['scenario_list'] = scenario_list
        return context

class SubmitSettingsView(FormView):

    template_name = "new_template.html"
    form_class = OpenstackSettingsForm

#     # add the request to the kwargs
#     def get_form_kwargs(self):
#         kwargs = super(RegisterView, self).get_form_kwargs()
#         kwargs['request'] = self.request
#         return kwargs

    def form_invalid(self, form):
        return super(SubmitSettingsView, self).form_valid(form)

    def form_valid(self, form):
        OpenstackSettings.objects.all().delete()
        config = form.save()
        if self.request.POST.get('summary-table-settings', 0) == 'scenario':
            try:
                iplist_file_path = os.path.join(settings.IPLIST_DESTINATION, 'iplist.yaml')


		iplist_content = ""
                iplist_scenario ={}
                selected_scenario = self.request.POST.get('selected-scenario',None)
                processed_iplist_content = {}
		processed_iplist_text = {}
                if os.path.isfile(iplist_file_path):
                    with open(iplist_file_path, 'r') as content_file:
                        iplist_content = content_file.read()

		    if iplist_content:
                   	processed_iplist_content = yaml.load(iplist_content)
                nodes = int(self.request.POST.get('scenario_node_number', 0))
                iplist = {}
                for x in range(nodes):
                    hostname = self.request.POST.get('scenario_hostname__'+str(x), "")
                    ip = self.request.POST.get('scenario_ip__'+str(x), "")
                    role = self.request.POST.get('role-'+str(x), "")
		    pndn = 'sys/chassis-'+self.request.POST.get('chassis_number__'+str(x), 0)+'/blade-'+self.request.POST.get('blade_number__'+str(x), 0)
		    print pndn
                    if hostname and ip and role:

			iplist_scenario['name:'+hostname] = {'interfaces':{'eth0':{'ip':ip,'dnsname':hostname}},'role':role}



               # traverse_tree(processed_iplist_content)
                processed_iplist_text[selected_scenario] = iplist_scenario
                processed_iplist_content['iplist'] = processed_iplist_text
                traverse_tree(processed_iplist_content)
		
                with open(iplist_file_path, 'w') as content_file:
                    content_file.write( yaml.safe_dump(processed_iplist_content, default_flow_style=False))

                cobbler_file_path = os.path.join(settings.COBBLER_DESTINATION, 'cobbler.yaml')
                cobbler_content = ""
                processed_cobbler_content = {}
                if os.path.isfile(cobbler_file_path):
                    with open(cobbler_file_path, 'r') as content_file:
                        cobbler_content = content_file.read()
                    processed_cobbler_content = yaml.load(cobbler_content)
                for x in range(nodes):
                    hostname = self.request.POST.get('scenario_hostname__'+str(x), "")
                    ip = self.request.POST.get('scenario_ip__'+str(x), "")
                    role = self.request.POST.get('role-'+str(x), "")
                    if hostname and ip and role:
                        if hostname in processed_cobbler_content:
                            processed_cobbler_content[hostname]['hostname'] = hostname
                            processed_cobbler_content[hostname]['power_address'] =ip
                        else:
                            processed_cobbler_content[hostname] = {'hostname': hostname, 'power_address':ip}

                traverse_tree(processed_cobbler_content)
#                with open(cobbler_file_path, 'w') as content_file:
#                    content_file.write( yaml.safe_dump(processed_cobbler_content, default_flow_style=False))
            except Exception, e:
                pass
        else:
            NodeSettings.objects.all().delete()
            nodes = int(self.request.POST.get('node_number', 0))
            for x in range(nodes):
                node_name = self.request.POST.get('node_name__'+str(x), "")
                node_number = x
                chassis_number = int(self.request.POST.get('chassis_number__'+str(x), 0))
                blade_number = int(self.request.POST.get('blade_number__'+str(x), 0))
                aio = (x == int(self.request.POST.get('aio', 0)))
                compute = ('compute__' + str(x) ) in self.request.POST
                network = (x == int(self.request.POST.get('network', 0)))
                swift = ('swift__' + str(x) ) in self.request.POST
                cinder = ('cinder__' + str(x) ) in self.request.POST
                NodeSettings(node_name=node_name, node_number=node_number, aio=aio, compute=compute, network=network,
                             swift=swift, cinder=cinder, chassis_number=chassis_number, blade_number=blade_number).save()
        config_nodes = serializers.serialize('python', NodeSettings.objects.all())
        config_settings = serializers.serialize('python', OpenstackSettings.objects.all())
        config_text = render_to_string('config.template', {'nodes': config_nodes, 'settings':config_settings})
        config_file_path = os.path.join(settings.PROJECT_PATH, 'openstack_settings.txt')
        config_file = open(config_file_path, 'w')
        config_file.write(config_text)
        config_file.close()
        construct_conf_file(config=config, query_str_dict = self.request.POST)
        return super(SubmitSettingsView, self).form_valid(form)

    def get_success_url(self):
        return reverse('settings')

class NodeDiscoveryView(JSONResponseMixin, AjaxResponseMixin, View):
    def post_ajax(self, request, *args, **kwargs):
        hostname = request.POST.get('hostname', '')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        script_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scripts', 'NodeInventory.py')
        print script_path
        print '*'*50
        try:
            subprocess.call(['python', script_path , '-i' , hostname , '-u' , username , '-p', password,])
        except Exception, e:
            pass
        print os.path.join('python', script_path , '-i' , hostname , '-u' , username , '-p', password)
        #file_path = os.path.join('.', hostname+'_inventory.yaml')
        #file_path = os.path.join(settings.PROJECT_PATH, '..', hostname+'_invenotry.yaml')
        #file_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scripts', '10.1.1.130_invenotry.yaml') #debug file
        file_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scripts', hostname+'_inventory.yaml')
        content = ""
        with open(file_path, 'r') as content_file:
            content = content_file.read()

        processed_content = yaml.load(content)

        json_list = []
        for chassis, chassis_dict in processed_content.iteritems():
            for node, node_dict in chassis_dict.iteritems():
                html_result = ''
                text_result = ''
                cpu_type = ''
                adaptor_type = ''
                if len(node_dict['ProcessorUnits']) >0:
                    for cpu, cpu_dict in node_dict['ProcessorUnits'].iteritems():
                        cpu_type = cpu_dict['model']
                if len(node_dict['AdaptorUnits']) >0:
                    for adaptor, adaptor_dict in node_dict['AdaptorUnits'].iteritems():
                        adaptor_type = adaptor_dict['model']
                html_result += chassis + '/' + node + '<br>'
                if len(node_dict['assignedToDn']) >0:
                    html_result += 'Service Profile Associated: ' + node_dict['assignedToDn'] + '<br>'


                html_result += 'CPU: ' + node_dict['numOfCpus'] + '<br>'
                html_result += 'CPU Type: ' + cpu_type + '<br>'
                html_result += 'Mem: ' + node_dict['availableMemory'] + '<br>'
                html_result += 'Disks: ' + str(len(node_dict['StorageUnits'])) + '<br>'
                html_result += 'Adaptors: ' + node_dict['numOfAdaptors'] + '<br>'
                html_result += 'Adaptor Type: ' + adaptor_type + '<br>'

                text_result += chassis + '/' + node + '\n'
                if len(node_dict['assignedToDn']) >0:
                    text_result += 'Service Profile: ' + node_dict['assignedToDn'] + '\n'
                text_result += 'CPU: ' + node_dict['numOfCpus'] + '\n'
                text_result += 'CPU Type: ' + cpu_type + '\n'
                text_result += 'Mem: ' + node_dict['availableMemory'] + '\n'
                text_result += 'Disks: ' + str(len(node_dict['StorageUnits'])) + '\n'
                text_result += 'Adaptors: ' + node_dict['numOfAdaptors'] + '\n'
                text_result += 'Adaptor Type: ' + adaptor_type + '\n'

                json_list.append([html_result, text_result, chassis.split('-')[1], node.split('-')[1], ], )
        return self.render_json_response(json_list)


class ScenarioDiscoveryView(JSONResponseMixin, AjaxResponseMixin, View):
    def post_ajax(self, request, *args, **kwargs):
        hostname = request.POST.get('hostname', '')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        scenario_name = request.POST.get('scenario_name', '')
        script_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scripts', 'NodeInventory.py')
#        try:
 #           subprocess.call(['python', script_path , '-i' , hostname , '-u' , username , '-p', password,])
  #      except Exception, e:
   #         print e
    #        print script_path
     #       pass
        #file_path = os.path.join('.', hostname+'_inventory.yaml')
        #file_path = os.path.join(settings.PROJECT_PATH, '..', hostname+'_invenotry.yaml')
        #file_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scripts', '10.1.1.130_invenotry.yaml') #debug file
        file_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scripts', hostname+'_inventory.yaml')
        content = ""
        with open(file_path, 'r') as content_file:
            content = content_file.read()

        processed_content = yaml.load(content)


        scenario_path = os.path.join(settings.PROJECT_PATH, 'static-raw', 'scenarios', scenario_name+'.yaml')
        scenario_content = ""
        with open(scenario_path, 'r') as content_file:
            scenario_content = content_file.read()
        processed_scenario_content = yaml.load(scenario_content)

        json_list = []
        for chassis, chassis_dict in processed_content.iteritems():
            for node, node_dict in chassis_dict.iteritems():
                html_result = ''
                text_result = ''
                cpu_type = ''
                adaptor_type = ''
                node_name = ''
                if len(node_dict['ProcessorUnits']) >0:
                    for cpu, cpu_dict in node_dict['ProcessorUnits'].iteritems():
                        cpu_type = cpu_dict['model']
                if len(node_dict['AdaptorUnits']) >0:
                    for adaptor, adaptor_dict in node_dict['AdaptorUnits'].iteritems():
                        adaptor_type = adaptor_dict['model']
                html_result += chassis + '/' + node + '<br>'
                if len(node_dict['assignedToDn']) >0:
                    html_result += 'Service Profile Associated: ' + node_dict['assignedToDn'] + '<br>'


                html_result += 'CPU: ' + node_dict['numOfCpus'] + '<br>'
                html_result += 'CPU Type: ' + cpu_type + '<br>'
                html_result += 'Mem: ' + node_dict['availableMemory'] + '<br>'
                html_result += 'Disks: ' + str(len(node_dict['StorageUnits'])) + '<br>'
                html_result += 'Adaptors: ' + node_dict['numOfAdaptors'] + '<br>'
                html_result += 'Adaptor Type: ' + adaptor_type + '<br>'

                text_result += chassis + '/' + node + '\n'
                if len(node_dict['assignedToDn']) >0:
                    text_result += 'Service Profile: ' + node_dict['assignedToDn'] + '\n'

                text_result += 'CPU: ' + node_dict['numOfCpus'] + '\n'
                text_result += 'CPU Type: ' + cpu_type + '\n'
                text_result += 'Mem: ' + node_dict['availableMemory'] + '\n'
                text_result += 'Disks: ' + str(len(node_dict['StorageUnits'])) + '\n'
                text_result += 'Adaptors: ' + node_dict['numOfAdaptors'] + '\n'
                text_result += 'Adaptor Type: ' + adaptor_type + '\n'

                json_list.append([ chassis.split('-')[1], node.split('-')[1], html_result, text_result, ], )

        role_list = []
        for role, role_dict in processed_scenario_content['roles'].iteritems():
            role_list.append(role)

        json_list.sort()

        return self.render_json_response({'nodes':json_list, 'roles': role_list})
