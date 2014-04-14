import os
import sys
import xmlrpclib
import logging
import yaml


cobbler_server='127.0.0.1'
cobbler_user = 'cobbler'
cobbler_password = ''

# check if the profile exists already.
def isProfileExists(profileName):
        logging.debug('isProfileExists - ' + profileName)
        cobbler_handle = xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
        is_exists = cobbler_handle.find_profile({"name":profileName})
        if (is_exists):
                logging.debug('[Info] Profile ' + profileName + ' exists')
                return True
        pass
        return False
pass

# Write node info to cobbler.yaml file. Which later processed by cobbler.
def addSystemInCobblerConfFile(in_name, in_power_address, in_mac1, in_ip):

	logging.debug('In addSystemInCobblerConfFile')
	cobbler_node = {'hostname' : in_name,
        		'power_address' : in_power_address,
			'interfaces' : {'eth0' : { 'mac-address' : in_mac1,
						  'dns-name' : in_name,
						  'ip-address' : in_ip,
						  'static' : "0" 
						 }
					}
			}

	cobbler_nodes_file_name = "/etc/puppet/data/cobbler/cobbler.yaml"
	logging.debug('cobbler_nodes_file_name')
	cobbler_nodes_file = open(cobbler_nodes_file_name, 'r')
	yaml_cobbler_nodes = yaml.safe_load(cobbler_nodes_file)
	cobbler_nodes_file.close()

	if yaml_cobbler_nodes and yaml_cobbler_nodes.keys() and in_name in yaml_cobbler_nodes.keys():
		logging.debug('Node:%s entry already exists, just update the entry' % (in_name))
		yaml_cobbler_nodes[in_name] = cobbler_node
	else:
		yaml_cobbler_nodes[in_name] = cobbler_node
		logging.debug('Node:%s entry does not exists in cobbler.yaml, update cobbler.yaml' % (in_name))
	pass

	# Write the changes to role_mappings file
	cobbler_nodes_file = open(cobbler_nodes_file_name, 'w')
	yaml.safe_dump(yaml_cobbler_nodes, cobbler_nodes_file, default_flow_style=False)
	cobbler_nodes_file.close()


pass



# This function is to add a system to the given profile
def addSystem(name, profile_name, mac_address, ip_address):
        try:
                logging.debug('addSystem name:%s profile:%s mac:%s ' % (name, profile_name, mac_address))
                cobbler_handle = xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
                ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
                system_id = cobbler_handle.new_system(ltoken)
                cobbler_handle.modify_system(system_id, "name", name, ltoken)
                cobbler_handle.modify_system(system_id,'modify_interface', {
                        "macaddress-eth0"   : mac_address,
                        "ipaddress-eth0"   : ip_address,
                        "dnsname-eth0"      : name,
                        }, ltoken)
                cobbler_handle.modify_system(system_id, 'kickstart', "/etc/cobbler/preseed/cisco-preseed.iso", ltoken);      
                cobbler_handle.modify_system(system_id, "profile", profile_name, ltoken)

                cobbler_handle.save_system(system_id, ltoken)
                cobbler_handle.sync(ltoken)
                logging.debug('Added/Updated system in cobbler')
        except Exception, err:
                logging.debug("4Exception:" + str(err))
        pass
pass


# This function is to update system info in cobbler db
def updateSystem(name, profile_name, mac_address, ip_address):
        cobbler_handle =  xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
        ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
        system_id = cobbler_handle.new_system(ltoken)
        cobbler_server_conn.modify_system(system_id, "name", name, ltoken)
        cobbler_server_conn.modify_system(system_id,'modify_interface', {
                "macaddress-eth1"   : mac_address,
                "dnsname-eth1"      : name,
                }, ltoken)
        cobbler_server_conn.modify_system(system_id, "profile", profile_name, ltoken)

        cobbler_server_conn.save_system(system_id, ltoken)
        cobbler_server_conn.sync(ltoken)
pass


# This function is to remove host from cobbler db
def removeHost(name):
        try:
                logging.debug('removeHost name:%s ' % name)
                cobbler_handle = xmlrpclib.Server("http://"+cobbler_server+"/cobbler_api")
                ltoken = cobbler_handle.login(cobbler_user, cobbler_password)
                cobbler_handle.remove_system(name, ltoken)
                cobbler_handle.sync(ltoken)
                logging.debug('Removed system from %s' %  app_name)
        except Exception, err:
                logging.debug("5Exception:" + str(err))
        pass
pass

