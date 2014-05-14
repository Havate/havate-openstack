import sys
import os
import re
import ast
import time
import daemon
import logging
import yaml
from UcsSdk import *
from passlib.apps import custom_app_context as pwd_context
from jinja2 import Template, Environment, FileSystemLoader
from UcsUtils import *
from ConfUtils import *
from CobblerUtils import *

def get_quote_string(in_str):
	return "%s%s%s" % ('"', in_str, '"')
pass

def callback_lsServer(mce):
        """ Event listener callback function. This checks for the event type and
            updates the nodes in Openstack cluster nodes list. Also applies the
            new configuration to puppet.
        """
        logging.debug('Received a New Service Profile Event: ' + str(mce.mo.classId))
        logging.debug("service-profile DN:%s association status:%s" % (mce.mo.getattr("Dn"), mce.mo.getattr(LsServer.ASSOC_STATE)))
        try:
                ucsmHost = UcsmHost(os.environ['UCS_HOSTNAME'], os.environ['UCS_USER'], os.environ['UCS_PASSWORD'], "", YesOrNo.FALSE)
        except Exception, err:
                logging.debug('EException' + str(err))
        pass

        # If the service-profile is removed/deleted, delete system from openstck cluster
        if (Status.DELETED == str(mce.mo.getattr(LsServer.STATUS))):
                try:
                        consumer = ServiceProfileConsumerFactory(os.environ['APP_NAME'])
                        consumer.removeHost(getRn(mce.mo.getattr("Dn")))
                except Exception, err:
                        logging.debug('6Exception: ' + str(err))
                pass
                logging.debug('Removed system')
        pass

        # if the association state is associated, then add the system to openstack cluster
        if (str(mce.mo.getattr(LsServer.ASSOC_STATE)) == LsServer.CONST_ASSOC_STATE_ASSOCIATED):
                try:
                        logging.debug('Creating ServiceProfileConsumerFactory for app-%s' % os.environ['APP_NAME'])
                        consumer = ServiceProfileConsumerFactory(os.environ['APP_NAME'])
                        logging.debug('ucsmHost-%s'% (ucsmHost.hostname))
                        consumer.updateHost(mce.mo.getattr("Dn"), ucsmHost)
                        logging.debug("Added System to - %s" % (os.environ['APP_NAME']) )
                except Exception, err:
                        logging.debug('7Exception: ' + str(err))
                pass
        pass
        logging.debug('end of event')
pass

def run_listener(in_ucsm_host):
	handle = UcsHandle()
	login = handle.Login(in_ucsm_host.hostname, in_ucsm_host.username, in_ucsm_host.password, autoRefresh=YesOrNo.TRUE)
	# Add an event handle to filter events based on classId = lsServer
	try:
		# Get the list of active event handles.
		is_listener_running = False
		while True:
			#handle.GetEventHandlers()
			# Check if there is a way to check the if the event channel is terminated. 
			# open new channel if already opened one is closed.
			if not is_listener_running:
				ev_lsServer = handle.AddEventHandler(classId = "LsServer", callBack = callback_lsServer)
				is_listener_running = True
			pass
			time.sleep(5)
		pass
	except Exception, err:
		logging.debug('Exception:' + str(err))
		import traceback, sys
		logging.debug('-'*60)
		traceback.print_exc(file=sys.stdout)
		logging.debug('-'*60)
pass



class ServiceProfileConsumer(object):

        def __init__(self, name):
                logging.debug("init %s" % name)
        pass

        def retrieveUcsConfig(self, name, inUcsmHost):
                logging.debug('retreiving UCS configuration')
                getUcsConfig(name, inUcsmHost)
        pass

        def startListener(self, inUcsmHost, inAppName, inCobblerName, inCobblerPwd):
                logging.debug('Starting UCS event listener')
                os.environ['UCS_HOSTNAME'] = inUcsmHost.hostname
                os.environ['UCS_USER'] = inUcsmHost.username
                os.environ['UCS_PASSWORD'] = inUcsmHost.password
                os.environ['APP_NAME'] = inAppName

                context = daemon.DaemonContext(
                                files_preserve = [
                                        fh.stream,
                                ],
                        )
                context.open()
                run_listener(inUcsmHost)
        pass


        def updateHost(self, inDn, inUcsmHost):
                logging.debug('Update Host for App-%s ucsm-%s' % (os.environ['APP_NAME'], inUcsmHost.hostname))
                updateHostInApp(inDn, inUcsmHost)
                logging.debug('Updated Host for App-%s' % os.environ['APP_NAME'])
        pass

        def configureUcsPolicies(self, in_conf_filename, inUcsmHost):
                """ Reads the configuration file and configures the
                    policies in UCS Manager.
                """
                logging.debug('In configureUcsPolicies')
                for line in file(in_conf_filename) :
                        if (line.startswith("#")):
                                continue
                        pass
                        logging.debug(line)
                        if (line.startswith("ServerPort")):
                                logging.debug(line[line.find("{"):])
                                logging.debug('sleep for 5 secs')
                                time.sleep(1)
                                createServerPort(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("MacPool")):
                                logging.debug(line[line.find("{"):])
                                createMacPool(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("OrgOrg")):
                                logging.debug(line[line.find("{"):])
                                createOrgOrg(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("LsRequirement")):
                                logging.debug(line[line.find("{"):])
                                createLsRequirement(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ServiceProfileInstance")):
                                logging.debug(line[line.find("{"):])
                                createSPInstance(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ServiceProfile")):
                                logging.debug(line[line.find("{"):])
                                createServiceProfile(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ServerPoolingPolicy")):
                                logging.debug(line[line.find("{"):])
                                createComputePoolingPolicy(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ServerPool")):
                                logging.debug(line[line.find("{"):])
                                createServerPool(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ComputeAutoconfigPolicy")):
                                logging.debug(line[line.find("{"):])
                                createComputeAutoconfigPolicy(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("IpPool")):
                                logging.debug(line[line.find("{"):])
                                createIpPool(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("Vnic")):
                                logging.debug(line[line.find("{"):])
                                createVnicEther(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ServerQualifier")):
                                logging.debug(line[line.find("{"):])
                                createComputeQual(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("RackServerQualifier")):
                                logging.debug(line[line.find("{"):])
                                createComputeQualRack(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("ScrubPolicy")):
                                logging.debug(line[line.find("{"):])
                                createComputeScrubPolicy(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("UplinkPort")):
                                logging.debug(line[line.find("{"):])
                                createUplink(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("Vlan")):
                                logging.debug(line[line.find("{"):])
                                createVlan(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("StorageLocalDiskConfigPolicy")):
                                logging.debug(line[line.find("{"):])
                                createStorageLocalDiskConfigPolicy(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("LsbootPolicy")):
                                logging.debug(line[line.find("{"):])
                                createLsbootPolicy(inUcsmHost, line[line.find("{"):])
                        elif (line.startswith("LsServerBinding")):
                                logging.debug(line[line.find("{"):])
                                createLsBinding(inUcsmHost, line[line.find("{"):])
                        pass
                pass
                logging.debug('Configuration Completed.')
        pass
pass

class Cobbler(ServiceProfileConsumer):
        def __init__(self, name):
                super(Cobbler, self).__init__(name)
                logging.debug("Cobbler init %s"% name)
        pass

        def addHost(self, ucsmHost, name, macAddr, ipAddr, inLsServer):
                profile_name = getRn(inLsServer.getattr(LsServer.OPER_SRC_TEMPL_NAME))
                logging.debug('Adding server-%s macAddr-%s ipAddr-%s profile-%s'%(name, macAddr, ipAddr, profile_name))
                #check if the profile exists.
                if inLsServer.getattr(LsServer.OPER_SRC_TEMPL_NAME) != "" :
                        is_exists = isProfileExists(profile_name)
                        if not is_exists:
                                addSystem(name, 'default', macAddr)
                        else:
                                addSystem(name, profile_name, macAddr)#, ipAddr)
                        pass
                pass

        pass

        def removeHost(self, name):
                logging.debug('Removing Host from cobbler %s' % name)
                removeHost(name)
        pass
pass


#
class Openstack(ServiceProfileConsumer):
        def __init__(self, name):
                super(Openstack, self).__init__(name)
                logging.debug("Openstack init %s " % name)
        pass


        def addHost(self, ucsmHost, hostName, inNics, inLsServer):
                """Writes the nodes info to confi file in yaml format."""

                # check if node exists, then remove
                self.removeHost(hostName)
		pnDn = inLsServer.getattr(LsServer.PN_DN)
		powerAddr = inLsServer.getattr(LsServer.DN)
		powerAddrStartIndex = powerAddr.index('org-root') + len('org-root/')
		powerAddrEndIndex = powerAddr.index('/ls-')
		if 'org-root/ls-' not in powerAddr:
        	        powerAddr = ucsmHost.hostname + ":" + powerAddr[powerAddrStartIndex:powerAddrEndIndex]
	        else:
			powerAddr = inLsServer.getattr(LsServer.NAME)
		pass

		logging.debug('powerAddr:' + powerAddr)
		in_ls_name = inLsServer.getattr(LsServer.NAME)

		logging.debug('sp-name:' + in_ls_name)
            	self.update_node(in_ls_name, in_ls_name, ucsmHost.hostname, powerAddr, in_ls_name, ucsmHost.username, ucsmHost.password, 'ucs', inNics)
        pass

        def update_node(self, in_pn_dn, in_ls_name, in_power_ip, in_power_address, in_power_id, in_power_admin, in_power_password, in_power_type, in_nics):

		#make sure the ip-address mapping is present.
                iplist_filename = os.path.join( os.path.abspath(os.path.dirname(__file__)), 'iplist.yaml')
		logging.debug("iplist.yaml @ " + iplist_filename)
		if not os.path.exists(iplist_filename):
			logging.debug("iplist.yaml doesn't exists @ " + iplist_filename)
		pass

		site_file = open(iplist_filename, 'r')
                
		yaml_site_file = yaml.safe_load(site_file)
		site_file.close()

		is_node_updated = False
		iplist_key = 'iplist'
		noderoles_key = 'noderoles'
		# iplist.yaml is not empty and has 'iplist' and 'noderoles' defined.
		if yaml_site_file and iplist_key in yaml_site_file.keys():
			if in_pn_dn in yaml_site_file[iplist_key].keys():
				if yaml_site_file[iplist_key][in_pn_dn] and 'role' in yaml_site_file[iplist_key][in_pn_dn].keys() and yaml_site_file[iplist_key][in_pn_dn]['role'] == 'swift':
					logging.debug('node type is swift: zone %d' %(yaml_site_file[iplist_key][in_pn_dn]['swift_zone']))
					node = {
						'name': yaml_site_file[iplist_key][in_pn_dn]['name'],
						'role': yaml_site_file[iplist_key][in_pn_dn]['role'],
						'power_address': in_power_address,
						'power_id': in_power_id,
						'power_user': in_power_admin,
						'power_password': in_power_password,
						'power_type': in_power_type,
						'swift_zone': yaml_site_file[iplist_key][in_pn_dn]['swift_zone'],
						'interfaces': {}
						}
				else:
					node = {
						'name': yaml_site_file[iplist_key][in_pn_dn]['name'],
						'role': yaml_site_file[iplist_key][in_pn_dn]['role'],
						'power_address': in_power_address,
						'power_id': in_power_id,
						'power_user': in_power_admin,
						'power_password': in_power_password,
						'power_type': in_power_type,
						'interfaces': {}
						}
				pass
				for if_id in xrange(0, len(in_nics)):
					node['interfaces']['eth' + str(if_id)] = {}
					node['interfaces']['eth' + str(if_id)]['mac'] = in_nics[if_id]
					node['interfaces']['eth' + str(if_id)].update(yaml_site_file[iplist_key][in_pn_dn]['interfaces']['eth' + str(if_id)])
					node['interfaces']['eth' + str(if_id)]['ip'] = yaml_site_file[iplist_key][in_pn_dn]['interfaces']['eth' + str(if_id)]['ip']
					node['interfaces']['eth' + str(if_id)]['dnsname'] = yaml_site_file[iplist_key][in_pn_dn]['interfaces']['eth' + str(if_id)]['dnsname']
				pass
				logging.debug("noderoles_key:" + noderoles_key)
				logging.debug("yaml_site_file.keys():")
				logging.debug(yaml_site_file.keys()) 
				logging.debug("node['role']:" + node['role'])
				logging.debug("yaml_site_file[noderoles_key].keys():")
				logging.debug(yaml_site_file[noderoles_key].keys())
				if noderoles_key in yaml_site_file.keys() and node['role'] not in yaml_site_file[noderoles_key].keys():
					logging.debug('Node role %s not supported, discarding node %s' % (node['role'], node['name']))
					return
				pass

				role_mappings_file_name = "/etc/puppet/data/role_mappings.yaml"
				if not os.path.exists(role_mappings_file_name):
					role_mappings_file = open(role_mappings_file_name, 'w')
					role_mappings_file.close()
				pass

				role_mappings_file = open(role_mappings_file_name, 'r')
				yaml_role_mappings = yaml.safe_load(role_mappings_file)
				role_mappings_file.close()

				if yaml_role_mappings and yaml_role_mappings.keys() and node['name'] in yaml_role_mappings.keys():
					logging.debug('Node:%s entry already exists, just update the entry' % (node['name']))
					yaml_role_mappings[node['name']] = node['role']
				else:
					yaml_role_mappings[node['name']] = node['role']
					logging.debug('Node:%s entry does not exists in role_mappings, update role_mappings' % (node['name']))
				pass

				# Write the changes to role_mappings file
				role_mappings_file = open(role_mappings_file_name, 'w')
				yaml.safe_dump(yaml_role_mappings, role_mappings_file, default_flow_style=False)
				role_mappings_file.close()
				is_node_updated = True

				# Update node entry in cobbler
				logging.debug('Add cobbler node in cobbler.yaml')
				addSystemInCobblerConfFile(node)
				addSystem(node)
				logging.debug('Updated node:%s entry in cobbler' %(node['name']))

			else:
				logging.debug('iplist entry doesn\'t exist, skipping node %s' % (node['name']))
			pass
		else:
			logging.debug('iplist is not defined')
		pass

	pass 


        # should do it in a separate thread, so it won't block the current process.
        def invokePuppetApply(self):
                """It applies the puppet configuration."""
                logging.debug('invoking puppet apply -v /etc/puppet/manifests/site.pp')
                os.system('puppet apply -v /etc/puppet/manifests/site.pp')
                pass
        pass


        def removeHost(self, serverName):
                """This function removes the system from the Openstack configuration
                   file and updates the same. Also does Puppet apply to reflect the
                   new configuration file changes.
                """
		role_mappings_file_name = "/etc/puppet/data/role_mappings.yaml"

		if not os.path.exists(role_mappings_file_name):
			logging.debug("File role_mappings.yaml is not present, No need to proceed further")
			return
		pass
	
                logging.debug('removing Host from Openstack %s' % serverName)
                logging.debug("In Openstack.removeHost()")
                role_mappings_file = open(role_mappings_file_name, "r")
                yaml_role_mappings = yaml.safe_load(role_mappings_file)
                role_mappings_file.close()

                #check if the node already exists.
                if yaml_role_mappings and yaml_role_mappings.keys() and serverName in yaml_role_mappings.keys():
			del yaml_role_mappings[serverName]
			# Write the remaining nodes to yaml DB and do 'puppet apply'
			role_mappings_file = open("/etc/puppet/data/role_mappings.yaml", 'w')
			yaml.safe_dump(yaml_role_mappings, role_mappings_file, default_flow_style=False)
			role_mappings_file.close()
			#self.updateSiteFile()

			# Need to remove the entry in cobbler
	                logging.debug('Removing Host from cobbler %s' % serverName)
        	        removeHost(serverName)
			return	
		else:
			logging.debug('role_mappings.yaml is empty or key doesn\'t exists.')
		pass
        pass
pass


class Cloudstack(ServiceProfileConsumer):
        pass

class Hadoop(ServiceProfileConsumer):
        pass


class ServiceProfileConsumerFactory(object):
        consumers = {'openstack':Openstack, 'cobbler':Cobbler, 'cloudstack':Cloudstack, 'hadoop':Hadoop}

        def __new__(klass, consumer):
                logging.debug("creating new consumer-%s"%consumer)
                return ServiceProfileConsumerFactory.consumers[consumer](consumer)
        pass
pass


#
def getUcsConfig(inAppName, inUcsmHost):
        try:
                #logging.debug('HostName'+inUcsmHost.hostname + " username:"+ inUcsmHost.username + " password:"+ inUcsmHost.password)
                handle = UcsHandle()
                login = handle.Login(inUcsmHost.hostname, inUcsmHost.username, inUcsmHost.password)
                if login == False:
                        logging.debug('Login Failed')
                        sys.exit(0)
                pass

                # Adding systems is common across integration applications.
                lsServers = handle.GetManagedObject(None, LsServer.ClassId(), None, dumpXml = False)
                for lsServer in lsServers:
                        logging.debug('Adding/Updating server - ' + lsServer.getattr(LsServer.DN))
                        # Create Filter to get all chassis info, and iterate through each chassis to get servers under it.
                        addUcsServer(handle, inUcsmHost, lsServer.getattr(LsServer.DN), lsServer, inAppName)
                pass
        except Exception, err:
                logging.debug('2Exception:' + str(err))
                print '-'*60
		import traceback
                traceback.print_exc(file=sys.stdout)
                print '-'*60
                print('Exception:' + str(err))

        pass
pass


#
def updateHostInApp(inDn, inUcsmHost):
        try:
                #logging.debug("In updateHostInApp"+ inUcsmHost.hostname + inUcsmHost.username + inUcsmHost.password)
                handle = UcsHandle()
#                login = handle.Login(ucsmHost.hostname, ucsmHost.username, ucsmHost.password)
                login = handle.Login(inUcsmHost.hostname, inUcsmHost.username, inUcsmHost.password)
                if login == False:
                        logging.debug('Login Failed')
                        sys.exit(0)
                pass

                # Adding systems is common across integration applications.
                lsServers = handle.GetManagedObject(None, LsServer.ClassId(), {LsServer.DN:inDn}, dumpXml = True)
                for lsServer in lsServers:
                        logging.debug('Adding/Updating server - ' + lsServer.getattr(LsServer.DN))
                        # Create Filter to get all chassis info, and iterate through each chassis to get servers under it.
                        addUcsServer(handle, inUcsmHost, lsServer.getattr(LsServer.DN), lsServer, os.environ['APP_NAME'])
                pass
                handle.Logout()
        except Exception, err:
                logging.debug('3Exception:' + str(err))
        pass
pass


#
def addUcsServer(handle, inUcsmHost, inDn, lsServer, inAppName):
        """ Get the ComputeBlades information, adds to Openstack
            If the boot order has LAN boot enabled.
        """
        logging.debug('In addUcsServer')
        inFilter = FilterFilter()
        eqFilter = EqFilter()
        eqFilter.Class = "computeBlade"
        eqFilter.Property = "assignedToDn"
        eqFilter.Value = inDn
        inFilter.AddChild(eqFilter)
        computeBlades = handle.ConfigResolveClass(ComputeBlade.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml = False)
        if (computeBlades.errorCode == 0):
                # for each computeBladeMo, get the lsbootDef Info.
                for blade in computeBlades.OutConfigs.GetChild():
                        lsbootDef = getLsbootDef(handle, blade)
                        for bootDef in lsbootDef.OutConfigs.GetChild():
                                # only one LsbootDef will be present, break once we got that info.
                                addHost(handle, inUcsmHost, bootDef, blade, lsServer, inAppName)
                                pass
                        pass
                pass
        pass

        inFilter = FilterFilter()
        eqFilter = EqFilter()
        eqFilter.Class = "computeRackUnit"
        eqFilter.Property = "assignedToDn"
        eqFilter.Value = inDn
        inFilter.AddChild(eqFilter)
        computeRackUnits = handle.ConfigResolveClass(ComputeRackUnit.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml = False)
        if (computeRackUnits.errorCode == 0):
                # for each computeackUnitMo the lsbootDef Info.
                for blade in computeRackUnits.OutConfigs.GetChild():
                        lsbootDef = getLsbootDef(handle, blade)
                        for bootDef in lsbootDef.OutConfigs.GetChild():
                                # only one LsbootDef will be present, break once we got that info.
                                addHost(handle, inUcsmHost, bootDef, blade, lsServer, inAppName)
                                pass
                        pass
                pass
        pass


pass





#
def addHostToApp(inUcsmHost, inHostName, inNics, inLsServer, inAppName):
        """ Adds system to respective Application.
        """
        logging.debug('Adding host:%s to App:%s' % (inHostName, inAppName) )
        consumer = ServiceProfileConsumerFactory(inAppName)
        consumer.addHost(inUcsmHost, inHostName, inNics, inLsServer)
pass

def getHostNamePrefix(inLsServer, inUcsmHost):
	specialChars = ['\'', '.', '!', '#', '$', '@', '%', '^', '&', '(', ')','*',';',':', '_']

        logging.debug("hostname:" + inUcsmHost.hostname + "  afterReplace:"+ re.sub('[%s]' % ''.join(specialChars), '-', inUcsmHost.hostname))
        
	return  getRn(inLsServer.getattr(LsServer.OPER_SRC_TEMPL_NAME)) + "-" + re.sub('[%s]' % ''.join(specialChars), '-', inUcsmHost.hostname)

pass

#
def getHostNameFromIPList(inLsServerName):
	if inLsServerName in iplist.keys():
		return iplist[inLsServerName]['name']
	pass
	return 
pass		
	

# This function is add the system to cobbler
def addHost(connHandle, inUcsmHost, lsbootDef, inCompServer, inLsServer, inAppName):
        logging.debug('In addHost')
        # lsbootDef contains only one LsbootLan Mo
        bootLan = getLsbootLan(connHandle, lsbootDef)
	nics = []
        for lsbootLan in bootLan:
                if ((lsbootLan != 0) and (isinstance(lsbootLan, ManagedObject) == True) and (lsbootLan.classId == "LsbootLan")):
                        for imagePath in lsbootLan.GetChild():
                                if ((imagePath != 0)):
                                        vnicEther = getVnicEther(connHandle, imagePath.getattr("VnicName"), inLsServer)
                                        if (vnicEther != 0):
						logging.debug("cwd:" + os.getcwd())
						iplist_file =  open(os.path.join( os.path.abspath(os.path.dirname(__file__)), 'iplist.yaml'))
						yaml_iplist = yaml.safe_load(iplist_file)
						iplist_file.close()
						if yaml_iplist and 'iplist' in yaml_iplist.keys() and inLsServer.getattr(LsServer.NAME) in yaml_iplist['iplist'].keys():
							logging.debug('getiplist')
							if_id = {'primary':'0', 'secondary':'1'}
							ipAddress = yaml_iplist['iplist'][inLsServer.getattr(LsServer.NAME)]['interfaces']['eth' + if_id.get(imagePath.getattr(LsbootLanImagePath.TYPE))]['ip']
							hostname = yaml_iplist['iplist'][inLsServer.getattr(LsServer.NAME)]['interfaces']['eth' + if_id.get(imagePath.getattr(LsbootLanImagePath.TYPE))]['dnsname']
							if ipAddress:
								nics.append(vnicEther[0].getattr(VnicEther.ADDR))
							else:
								logging.debug('skip adding node %s, no ip-address entry present' % inLsServer.getattr(LsServer.NAME) )
							pass
						else:
							logging.debug('skip adding node %s, no ip-address entry present' % inLsServer.getattr(LsServer.NAME) )
						pass
                                        pass
                                pass
                        pass
                pass
        pass
	if len(nics) > 0:
		logging.debug('No.of NICs configured in boot-order: %d' % (len(nics)))
		addHostToApp(inUcsmHost, hostname, nics, inLsServer, inAppName)
	pass
pass

