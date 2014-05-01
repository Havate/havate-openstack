import os
import sys
import xmlrpclib
import logging
import yaml


cobbler_server='127.0.0.1'
cobbler_user = 'cobbler'
cobbler_password = ''
cobbler_profile_name = 'precise-x86_64'

# check if the profile exists already.
def isProfileExists(profile_name):
        logging.debug('isProfileExists - ' + profile_name)
        cobbler_handle = xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
        is_exists = cobbler_handle.find_profile({"name": profile_name})
        if (is_exists):
                logging.debug('Profile ' + profile_name + ' exists')
                return True
        pass
        return False
pass

def addSystemInCobblerConfFile(node):
	""" Writes the nodes info to cobbler.yaml file."""
	logging.debug('In addSystemInCobblerConfFile')
	interfaces = {}
	for if_id in xrange(0, len(node['interfaces'])):
		interface = {}
		interface.update({'mac-address': node['interfaces']['eth' + str(if_id)]['mac']})
		interface.update({'dns-name': node['interfaces']['eth' + str(if_id)]['dnsname']})
		interface.update({'ip-address': node['interfaces']['eth' + str(if_id)]['ip']})
		interface.update({'static': '0'})
		interfaces.update({'eth%d' % if_id: interface})
	pass

	cobbler_node = {'hostname' : node['name'],
        		'power_address' : node['power_address'],
			'interfaces' : interfaces 
			}

	cobbler_nodes_file_name = "/etc/puppet/data/cobbler/cobbler.yaml"
	logging.debug('cobbler_nodes_file_name')
	cobbler_nodes_file = open(cobbler_nodes_file_name, 'r')
	yaml_cobbler_nodes = yaml.safe_load(cobbler_nodes_file)
	cobbler_nodes_file.close()

	if yaml_cobbler_nodes and yaml_cobbler_nodes.keys():
		yaml_cobbler_nodes[node['name']] = cobbler_node
		logging.debug('Node:%s added/updated in cobbler.yaml' % (node['name']))
	pass

	# Write the changes to role_mappings file
	cobbler_nodes_file = open(cobbler_nodes_file_name, 'w')
	yaml.safe_dump(yaml_cobbler_nodes, cobbler_nodes_file, default_flow_style=False)
	cobbler_nodes_file.close()
pass



# This function is to add a system to the given profile
def addSystem(node):
        try:
                logging.debug('addSystem name:%s profile:%s:' % (node['name'], cobbler_profile_name))
                cobbler_handle = xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
                ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
       	        system_id = cobbler_handle.new_system(ltoken)
               	cobbler_handle.modify_system(system_id, "name", node['name'], ltoken)
		for if_id in xrange(0, len(node['interfaces'])):
			interface = {}
			interface.update({'macaddress-eth%d' % (if_id): node['interfaces']['eth' + str(if_id)]['mac']})
			interface.update({'ipaddress-eth%d' % (if_id): node['interfaces']['eth' + str(if_id)]['ip']})
			interface.update({'dnsaddress-eth%d' % (if_id): node['interfaces']['eth' + str(if_id)]['dnsname']})
	                cobbler_handle.modify_system(system_id,'modify_interface', interface, ltoken)
		pass
		cobbler_handle.modify_system(system_id, 'kickstart', "/etc/cobbler/preseed/cisco-preseed", ltoken);
		cobbler_handle.modify_system(system_id, "profile", cobbler_profile_name, ltoken)
               	cobbler_handle.save_system(system_id, ltoken)
		cobbler_handle.sync(ltoken)
                logging.debug('Added system in cobbler')
        except Exception, err:
                logging.debug("Exception:" + str(err))
                import traceback, sys
                logging.error('-'*60)
                traceback.print_exc(file=sys.stdout)
                logging.error('-'*60)
        pass
pass


#this function is to add a system to the given profile
def updateSystem(node):
	try:
	        cobbler_handle =  xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
	        ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
	        system_id = cobbler_handle.new_system(ltoken)
       	 	cobbler_server_conn.modify_system(system_id, "name", node['name'], ltoken)
		for if_id in xrange(0, xrange(node['interfaces'])):
			interface = {}
                        interface.update({'macaddress-eth%d' % (if_id): node['interfaces']['eth' + str(if_id)]['mac']})
                        interface.update({'ipaddress-eth%d' % (if_id): node['interfaces']['eth' + str(if_id)]['ip']})
                        interface.update({'dnsaddress-eth%d' % (if_id): node['interfaces']['eth' + str(if_id)]['dnsname']})
		        cobbler_server_conn.modify_system(system_id,'modify_interface', interface, ltoken)
		pass
       	 	cobbler_server_conn.modify_system(system_id, "profile", cobbler_profile_name, ltoken)
	        cobbler_server_conn.save_system(system_id, ltoken)
       		cobbler_server_conn.sync(ltoken)
	except Exception, err:
		logging.debug('Exception' + str(err))
                import traceback, sys
                logging.error('-'*60)
                traceback.print_exc(file=sys.stdout)
                logging.error('-'*60)
	pass
pass

def is_system_exist(name):
	try:
		logging.debug('is_system_exist:%s' % (name))
		cobbler_handle = xmlrpclib.Server("http://" + cobbler_server +"/cobbler_api")
		ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
		sys = cobbler_handle.find_system({'name': name}) 
		if sys:
			logging.debug('is_system_exist: True')
			return True
		else:
			logging.debug('is_system_exist: False')
			return False
		pass
	except Exception, err:
                logging.debug("Exception:" + str(err))
                import traceback, sys
                logging.error('-'*60)
                traceback.print_exc(file=sys.stdout)
                logging.error('-'*60)
        pass
pass
	
# This function is to add a system to the given profile
def removeHost(name):
        try:
                logging.debug('removeHost name:%s' % name)
                cobbler_handle = xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
                ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
		if is_system_exist(name):
	                cobbler_handle.remove_system(name, ltoken)
        	        cobbler_handle.sync(ltoken)
                	logging.debug('Removed system:%s from openstack' % (name))
		else:
			logging.debug('system:%s does not exist in cobbler' % (name))
		pass
        except Exception, err:
                logging.debug("Exception:" + str(err))
                import traceback, sys
                logging.error('-'*60)
                traceback.print_exc(file=sys.stdout)
                logging.error('-'*60)
        pass
pass
