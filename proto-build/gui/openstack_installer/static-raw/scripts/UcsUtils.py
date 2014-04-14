import sys
import os
import ast
import time
import daemon
import logging
import yaml
from UcsSdk import *
from passlib.apps import custom_app_context as pwd_context
from jinja2 import Template, Environment, FileSystemLoader



# Applications supported
class AppName:
        OPENSTACK = "openstack"
        COBBLER = "cobbler"
pass

class UcsmHost:
        def __init__(self, hostname, username, password, conf_template, debug):
                self.hostname = hostname
                self.username = username
                self.password = password
                self.conf_template = conf_template
                self.debug = debug
        pass
pass

# function returns Rn for ServiceProfile instances.
def getRn(dn):
        return dn[dn.rfind("ls-")+3:]
pass


#
def addObjectToUcs(inUcsmHost, pDn, pClassId, classId, pList, inDn):
        """This function gets the session and configures the MO in UCS Manager
           If that doesn't exists. If the MO already exists, it just updates the MO.
        """
        try:
                handle = UcsHandle()
                login = handle.Login(inUcsmHost.hostname, inUcsmHost.username, inUcsmHost.password)
                if (login == False):
                        logging.debug('[Error]: Login Failed')
                        sys.exit(0)

                res = handle.GetManagedObject(None, pClassId, {"Dn":pDn}, dumpXml=inUcsmHost.debug)
                moRes = handle.GetManagedObject(None, classId, {"Dn":inDn}, dumpXml=inUcsmHost.debug)
                if not moRes:
                        result = handle.AddManagedObject(res, classId, pList, dumpXml=inUcsmHost.debug)
                else:
                        logging.debug('Mo exists, just updating')
                        result = handle.SetManagedObject(moRes, classId, pList, dumpXml=inUcsmHost.debug, force=True)
                pass

                handle.Logout()

        except Exception, err:
                print "1Exception:", str(err)
                import traceback, sys
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
        pass
pass


#
def getAdaptorHostEthIf(inConnHandle, inCompServer, inVnicName):
        inFilter = FilterFilter()

        andFilter0 = AndFilter()

        wcardFilter = WcardFilter()
        wcardFilter.Class = "adaptorHostEthIf"
        wcardFilter.Property = "dn"
        wcardFilter.Value = "%s/"%inCompServer.Dn
        andFilter0.AddChild(wcardFilter)

        eqFilter = EqFilter()
        eqFilter.Class = "adaptorHostEthIf"
        eqFilter.Property = "name"
        eqFilter.Value = inVnicName
        andFilter0.AddChild(eqFilter)

        inFilter.AddChild(andFilter0)

        adaptorHostEthIfs = inConnHandle.ConfigResolveClass(AdaptorHostEthIf.ClassId(), inFilter, YesOrNo.TRUE, dumpXml = False)
        if (adaptorHostEthIfs.errorCode == 0):
                return adaptorHostEthIfs.OutConfigs.GetChild()
        return
pass


#
def getHostAdaptorEthIf(handle, inComputeServer, inHostName, inImagePath, inAssignedToDn):
        logging.debug('[Info] Add System to Cobbler')
        hostEthIfs = getAdaptorHostEthIf(handle, inComputeServer, inImagePath.getattr("VnicName"))

        for hostEthIf in hostEthIfs:
                isExists = isSystemExists(hostEthIf.getattr("Mac"))
                logging.debug('Mac -' + hostEthIf.getattr("Mac"))
                if (not isExists):
                        logging.debug('[Info] cobbler system add --name=' + inHostName + \
                                        ' --interface=' + inImagePath.getattr("Type") + ' --mac=' + \
                                        hostEthIf.getattr("Mac") + ' --profile=' + getRn(inAssignedToDn))
                        if (inImagePath.getattr("Type") == "primary"):
                                addSystem(inHostName, getRn(inAssignedToDn), hostEthIf.getattr("Mac"))
                        elif (inImagePath.getattr("Type") == "secondary"):
                                updateSystem(inHostName, getRn(inAssignedToDn), hostEthIf.getattr("Mac"))
                else:
                        logging.debug('System exists')
                pass

        pass
pass

# This function is to retrieve LsbootDef of a particular server instance.
def getLsbootDef(connHandle, computeBlade):
        logging.debug('In getLsbootDef')

        inFilter = FilterFilter()
        wcardFilter = WcardFilter()
        wcardFilter.Class = "lsbootDef"
        wcardFilter.Property = "dn"
        wcardFilter.Value = "%s/"%computeBlade.Dn
        inFilter.AddChild(wcardFilter)

        lsbootDef = connHandle.ConfigResolveClass(LsbootDef.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml = False)
        return lsbootDef
pass

# This function is to get lsbootLan Info of lsbootDef
def getLsbootLan(connHandle, lsbootDef):
        logging.debug('In getLsbootLan')
        inFilter = FilterFilter()
        wcardFilter = WcardFilter()
        wcardFilter.Class = "lsbootLan"
        wcardFilter.Property = "dn"
        wcardFilter.Value = "%s/"%lsbootDef.getattr("Dn")
        inFilter.AddChild(wcardFilter)

        lsbootLan  = connHandle.ConfigResolveClass(LsbootLan.ClassId(), inFilter, YesOrNo.TRUE, dumpXml = False)
        if (lsbootLan.errorCode == 0):
                return lsbootLan.OutConfigs.GetChild()
        else:
                logging.debug('Failed to get lsbootLan')
        pass

pass

#
def getVnicEther(connHandle, inVnicName, inLsServer):
        logging.debug('In getVnicEther')
        inFilter = FilterFilter()

        andFilter0 = AndFilter()

        wcardFilter = WcardFilter()
        wcardFilter.Class = VnicEther.ClassId()
        wcardFilter.Property = "dn"
        wcardFilter.Value = "%s/"%inLsServer.Dn
        andFilter0.AddChild(wcardFilter)

        eqFilter = EqFilter()
        eqFilter.Class = VnicEther.ClassId()
        eqFilter.Property = "name"
        eqFilter.Value = inVnicName
        andFilter0.AddChild(eqFilter)

        inFilter.AddChild(andFilter0)

        vnicEther = connHandle.ConfigResolveClass(VnicEther.ClassId(), inFilter, YesOrNo.TRUE, dumpXml = False)

        if (vnicEther.errorCode == 0):
                return vnicEther.OutConfigs.GetChild()
        return 0
pass



# This function is add the system to cobbler
def addHostsToCobbler(connHandle, lsbootDef, inCompServer):
        logging.debug('In addHostsToCobbler')
        # lsbootDef contains only one LsbootLan Mo
        bootLan = getLsbootLan(connHandle, lsbootDef)
        for lsbootLan in bootLan:
                if ((lsbootLan != 0) and (isinstance(lsbootLan, ManagedObject) == True) and (lsbootLan.classId == "LsbootLan")):
                        for imagePath in lsbootLan.GetChild():
                                if ((imagePath != 0)):
                                        server_dn = inCompServer.Dn
                                        actual_name = server_dn.replace('/', '_')
                                        hostEthIfs = getHostAdaptorEthIf(connHandle, inCompServer, actual_name, imagePath, inCompServer.getattr("AssignedToDn"))
                                        pass
                                pass
                        pass
                pass
        pass
pass



#get the node-type based on service-profile prefix.
def getNodeType(inHostName):
        """ Retunrs the node-type, the convention is,
            if the node is strting with compute- returns compute node
            if the node is strting with control- returns control node.
        """
        if (inHostName.startswith("compute-")):
                return "compute"
        elif (inHostName.startswith("control-")):
                return "control"
        pass

        return " "
pass


# Add server-ports to system
def createServerPort(inUcsmHost, portsListStr):
        """Configure server-port in UCS Manager."""
        portList =  ast.literal_eval(portsListStr)
        logging.debug('creating server port')
        logging.debug(portList[FabricDceSwSrvEp.PORT_ID])
        logging.debug( portList[FabricDceSwSrvEp.SLOT_ID])
        dn = "fabric/server/sw-"+portList[FabricDceSwSrvEp.SWITCH_ID]+"/slot-"+portList[FabricDceSwSrvEp.SLOT_ID]+"-port-"+portList[FabricDceSwSrvEp.PORT_ID]
        pDn = "fabric/server/sw-"+portList[EtherPIo.SWITCH_ID]

        res = {FabricDceSwSrvEp.PORT_ID:portList[FabricDceSwSrvEp.PORT_ID], \
               FabricDceSwSrvEp.ADMIN_STATE:FabricDceSwSrvEp.CONST_ADMIN_STATE_ENABLED,\
               FabricDceSwSrvEp.SLOT_ID: portList[FabricDceSwSrvEp.SLOT_ID]}
        addObjectToUcs(inUcsmHost, pDn, FabricDceSwSrv.ClassId(), FabricDceSwSrvEp.ClassId(), res, dn)
pass

# Add Mac-pool to system
def createMacPool(inUcsmHost, macpoolListStr):
        """Configures the MAC pool in UCS Manager."""
        macpoolList = ast.literal_eval(macpoolListStr)
        logging.debug('creating MacPool) ')
        pDn = "org-root" # for now let it be under root org.
        dn = pDn+"/mac-pool-"+ macpoolList[MacpoolPool.NAME]

        res = {MacpoolPool.NAME:macpoolList[MacpoolPool.NAME]}
        #Add mac-pool
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), MacpoolPool.ClassId(), res, dn)
        # create mac-pool block.
        blockDn = dn + "block-"+macpoolList[MacpoolBlock.FROM]+"-"+macpoolList[MacpoolBlock.TO]

        blockStr = {MacpoolBlock.FROM:macpoolList[MacpoolBlock.FROM], \
                    MacpoolBlock.TO: macpoolList[MacpoolBlock.TO]}
        # Add MO to UCS Manager.
        addObjectToUcs(inUcsmHost, dn, MacpoolPool.ClassId(), MacpoolBlock.ClassId(), blockStr, blockDn)
pass

# Add service-profiles
def createServiceProfile(inUcsmHost, serviceprofileListStr):
        """Configures the server-profile template in UCS Manager."""
        logging.debug('create service-profile')
        serviceprofileList = ast.literal_eval(serviceprofileListStr)

        pDn = "org-root" # for now let it be under root org.
        dn = pDn + "/ls-"+serviceprofileList[LsServer.NAME]

        # create/update service-profile template.
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), LsServer.ClassId(), serviceprofileList, dn)
pass

# Add service-profiles
def createLsBinding(inUcsmHost, lsBindingListStr):
        """Binds server-profile with server."""
        logging.debug('create ls-binding')
	lsBindingList = ast.literal_eval(lsBindingListStr)

	pDn = lsBindingList['Org']

        lsServerDn = pDn + "/ls-" + lsBindingList[LsServer.NAME] # for now let it be under root org.
	lsServerList = {LsServer.SRC_TEMPL_NAME:lsBindingList[LsServer.SRC_TEMPL_NAME], LsServer.TYPE:"instance", LsServer.NAME:lsBindingList[LsServer.NAME]}
	addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), LsServer.ClassId(), lsServerList, lsServerDn)

        lsbindDn = lsServerDn + "/pn"
	lsbindList =  {LsBinding.PN_DN:lsBindingList[LsBinding.PN_DN]}
	addObjectToUcs(inUcsmHost, lsServerDn, LsServer.ClassId(), LsBinding.ClassId(), lsbindList, lsbindDn)

pass

#
def createComputeAutoconfigPolicy(inUcsmHost, autoconfigPolicyStr):
        """Configures Server auto-configuration policy in UCS Manager."""
        logging.debug('create compute-autoconfig-policy')
        autoconfigPolicyList = ast.literal_eval(autoconfigPolicyStr)

        pDn = "org-root" # ComputeAutoconfigPolicy is always added under org-root
        dn = pDn + "/autoconfig-" + autoconfigPolicyList[ComputeAutoconfigPolicy.NAME]

        # create/update auto-config-policy
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), ComputeAutoconfigPolicy.ClassId(), autoconfigPolicyList, dn)
pass



#
def createIpPool(inUcsmHost, ippoolStr):
        """Configures IP pool in UCS Manager."""
        logging.debug('creating ip-pool')
        poolList = ast.literal_eval(ippoolStr)

        pDn = "org-root" # Ippool is always added under org-root ?? is it so?
        dn = pDn + "/ip-pool-" + poolList[IppoolPool.NAME]

        # Create/Update ippool block
        ippoolList = {IppoolPool.NAME:poolList[IppoolPool.NAME]}
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), IppoolPool.ClassId(), ippoolList, dn)

        # Create/Update ippool-block under the ippool created above.
        ipblockDn = dn + "/block-" + poolList[IppoolBlock.FROM] + "-" + poolList[IppoolBlock.TO]

        ippoolBlockList = {IppoolBlock.DEF_GW:poolList[IppoolBlock.DEF_GW], \
                        IppoolBlock.FROM:poolList[IppoolBlock.FROM], \
                        IppoolBlock.TO:poolList[IppoolBlock.TO], \
                        IppoolBlock.PRIM_DNS:poolList[IppoolBlock.PRIM_DNS], \
                        IppoolBlock.SEC_DNS:poolList[IppoolBlock.SEC_DNS], \
                        IppoolBlock.SUBNET:poolList[IppoolBlock.SUBNET]}
        # Add Mo to ucsm
        addObjectToUcs(inUcsmHost, dn, IppoolPool.ClassId(), IppoolBlock.ClassId(), ippoolBlockList, ipblockDn)
pass


#def
def createVnicEther(inUcsmHost, vnicInfoStr):
        """Configures vNIC interface in UCS Manager."""
        logging.debug('creating vnic-ether')
        vnicInfoList = ast.literal_eval(vnicInfoStr)

        pDn = "org-root/ls-" + vnicInfoList["LsServer"]
        vnicEtherDn = pDn + "/ether-" + vnicInfoList[VnicEther.NAME]

	vnicEtherOrder = VnicEther.CONST_ORDER_UNSPECIFIED

	if VnicEther.ORDER in vnicInfoList.keys():
		logging.debug('VnicEther Order specified %s' %(vnicInfoList[VnicEther.ORDER]))
		vnicEtherOrder = vnicInfoList[VnicEther.ORDER]
	pass

        vnicEtherList = {VnicEther.NAME: vnicInfoList[VnicEther.NAME], \
                         VnicEther.SWITCH_ID: vnicInfoList[VnicEther.SWITCH_ID], \
                         VnicEther.IDENT_POOL_NAME: vnicInfoList[VnicEther.IDENT_POOL_NAME], \
			 VnicEther.ORDER: vnicEtherOrder}

        # add vnicEther to the LsServer
        addObjectToUcs(inUcsmHost, pDn, LsServer.ClassId(), VnicEther.ClassId(), vnicEtherList, vnicEtherDn)

        vnicEtherIfDn = vnicEtherDn + "/if-" + vnicInfoList["VlanName"]
        vnicEtherIfList = {VnicEtherIf.NAME: vnicInfoList["VlanName"], \
                           VnicEtherIf.DEFAULT_NET: vnicInfoList[VnicEtherIf.DEFAULT_NET]}

        # Add the Vlan to vnicEther created above.
        addObjectToUcs(inUcsmHost, vnicEtherDn, VnicEther.ClassId(), VnicEtherIf.ClassId(), vnicEtherIfList, vnicEtherIfDn)
pass

#
def createServerPool(inUcsmHost, serverPoolStr):
        """Configures Server Pool in UCS Manager."""
        logging.debug('create server-pool')
        serverPoolList = ast.literal_eval(serverPoolStr)

        pDn = "org-root" # should this be under org-root always
        serverPoolDn = pDn + "/compute-pool-" + serverPoolList[ComputePool.NAME]
        poolList = {ComputePool.NAME: serverPoolList[ComputePool.NAME]}

        # Create/Server Pool
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), ComputePool.ClassId(), poolList, serverPoolDn)
pass


#
def createComputeQual(inUcsmHost, computeQualStr):
        """Configures Server Qualification policy in UCS Manager."""
        logging.debug('create compute qual')
        computeQualList = ast.literal_eval(computeQualStr)

        pDn = "org-root" # is this added under org-root always?
        computeQualDn = pDn + "/blade-qualifier-" + computeQualList[ComputeQual.NAME]
        computeQualStr = {ComputeQual.NAME: computeQualList[ComputeQual.NAME]}

        # Create compute-qualifier
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), ComputeQual.ClassId(), computeQualStr, computeQualDn)

        computeChassisQualStr = {ComputeChassisQual.MIN_ID: computeQualList[ComputeChassisQual.MIN_ID], \
                                 ComputeChassisQual.MAX_ID: computeQualList[ComputeChassisQual.MAX_ID]}
        computeChassisQualDn = computeQualDn + "/chassis-from-" + computeQualList[ComputeChassisQual.MIN_ID] + "-to-" + computeQualList[ComputeChassisQual.MAX_ID]

        # Add Chassis Qualifier
        addObjectToUcs(inUcsmHost, computeQualDn, ComputeQual.ClassId(), ComputeChassisQual.ClassId(), computeChassisQualStr, computeChassisQualDn)
        logging.debug("computeQualDn"+computeQualDn)
        i = int(computeQualList[ComputeChassisQual.MIN_ID])
        while i <= (int(computeQualList[ComputeChassisQual.MAX_ID])):
                computeSlotQualDn = computeChassisQualDn + "/slot-from-" + computeQualList["SlotMinId"] + "-to-" + computeQualList["SlotMaxId"]
                computeSlotQualList = {ComputeSlotQual.MIN_ID: computeQualList["SlotMinId"], \
                                        ComputeSlotQual.MAX_ID: computeQualList["SlotMaxId"]}
                logging.debug("computeQual:" + computeChassisQualDn)
                addObjectToUcs(inUcsmHost, computeChassisQualDn, ComputeChassisQual.ClassId(), ComputeSlotQual.ClassId(), computeSlotQualList, computeSlotQualDn)
		i += 1
        pass
pass

#
def createComputeQualRack(inUcsmHost, computeQualRackStr):
	"""Configures Rack server Qualification policy in UCS Manager."""
	logging.debug('create compute rack qual')
        computeQualRackList = ast.literal_eval(computeQualRackStr)

	pDn = "org-root" # is this added under org-root always?
	computeQualRackDn = pDn + "/blade-qualifier-" + computeQualRackList[ComputeQual.NAME]
	computeQualRackStr = {ComputeQual.NAME: computeQualRackList[ComputeQual.NAME]}

	#create compute-rack-qualifier
	addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), ComputeQual.ClassId(), computeQualRackStr, computeQualRackDn)

	computeChassisQualRackStr = {ComputeRackQual.MIN_ID: computeQualRackList[ComputeRackQual.MIN_ID], \
				     ComputeRackQual.MAX_ID: computeQualRackList[ComputeRackQual.MAX_ID]}
	computeChassisQualRackDn = computeQualRackDn + "/rack-from-" + computeQualRackList["MinId"] + "-to-" + computeQualRackList["MaxId"]

	addObjectToUcs(inUcsmHost, computeQualRackDn, ComputeQual.ClassId(), ComputeRackQual.ClassId(), computeChassisQualRackStr, computeChassisQualRackDn)

pass


#
def createComputePoolingPolicy(inUcsmHost, computePoolingPolicyStr):
        """Configures Server Pooling policy in UCS Manager."""
        logging.debug('creating compute-pooling-policy')
        computePoolingPolicyList = ast.literal_eval(computePoolingPolicyStr)

        pDn = "org-root" # make this configurable?
        computePoolingPolicyDn = pDn + "/pooling-policy-" + computePoolingPolicyList[ComputePoolingPolicy.NAME]

        # Add Mo to UCS Manager
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), ComputePoolingPolicy.ClassId(), computePoolingPolicyList, computePoolingPolicyDn)
pass

#
def createComputeScrubPolicy(inUcsmHost, computeScrubgPolicyStr):
        """ Configures Scrub policy in UCS Manager."""
        logging.debug('create compute-scrub-policy')
        computeScrubPolicyList = ast.literal_eval(computeScrubgPolicyStr)

        pDn = "org-root"
        computeScrubgPolicyDn = pDn + "/scrub-" + computeScrubPolicyList[ComputeScrubPolicy.NAME]

        # Add Mo to UCS Manager
        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), ComputeScrubPolicy.ClassId(), computeScrubPolicyList, computeScrubgPolicyDn)
pass


# create VLAN instance 
def createVlan(inUcsmHost, fabricVlanStr):
        """ Configures VLAN in UCS Manager. """
        logging.debug('create vlan')
        fabricVlanList = ast.literal_eval(fabricVlanStr)

        pDn = "fabric/lan" # fabricLanCloud
        fabricVlanDn = pDn + "/net-" + fabricVlanList[FabricVlan.NAME]

        # Check if user is intended to create range of vLANs
        vlanIds = fabricVlanList[FabricVlan.ID]
        ids = vlanIds.rsplit('-')

        if (len(ids) == 2):
                for i in range(int(ids[0]), int(ids[1])):
                        fabricVlanRes = {FabricVlan.NAME: "vlan-os" + str(i), \
                                 FabricVlan.ID: i,\
                                 FabricVlan.SHARING: 'none',\
                                 FabricVlan.DEFAULT_NET: 'no'}
                        #Add Mo to UCS Manager
                        addObjectToUcs(inUcsmHost, pDn, FabricLanCloud.ClassId(), FabricVlan.ClassId(), fabricVlanRes, fabricVlanDn)
                pass
        else:
                fabricVlanRes = {FabricVlan.NAME: fabricVlanList[FabricVlan.NAME], \
                                 FabricVlan.ID: fabricVlanList[FabricVlan.ID],\
                                 FabricVlan.SHARING: fabricVlanList[FabricVlan.SHARING],\
                                 FabricVlan.DEFAULT_NET: fabricVlanList[FabricVlan.DEFAULT_NET]}

                # Add Mo to UCS Manager
                addObjectToUcs(inUcsmHost, pDn, FabricLanCloud.ClassId(), FabricVlan.ClassId(), fabricVlanRes, fabricVlanDn)
	pass
pass

# creates service profile instances.
def createSPInstance(inUcsmHost, lsServerInstancesStr):
	"""Creates N number of service profiles instantiating from SrcTempl."""
	logging.debug('creating SP Instances')
	lsServerInstancesList = ast.literal_eval(lsServerInstancesStr)

	handle = UcsHandle()
	login = handle.Login(inUcsmHost.hostname, inUcsmHost.username, inUcsmHost.password)
	if (login == False):
		logging.debug('[Error]: Login Failed')
		sys.exit(0)

	resMos = handle.GetManagedObject(None, LsServer.ClassId(), {"Name":lsServerInstancesList['SrcTempl']}, dumpXml=inUcsmHost.debug)
	if resMos:
		for spMo in resMos:
			handle.LsInstantiateNTemplate(spMo.getattr(LsServer.DN), lsServerInstancesList['NumberOf'], \
				lsServerInstancesList['NamePrefix'], lsServerInstancesList['TargetOrg'], dumpXml=True)
			pass
		pass
	pass

	handle.Logout()
pass

# create OrgOrg
def createOrgOrg(inUcsmHost, orgOrgStr):
        """Creates sub Orgs under org-root."""
        logging.debug('creating OrgOrg')
        orgOrgList = ast.literal_eval(orgOrgStr)

        orgOrgListRes = {OrgOrg.NAME:orgOrgList['Name']}

        pDn = orgOrgList['ParentDn']

        orgOrgDn = pDn + "/org-" + orgOrgList['Name']

        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), OrgOrg.ClassId(), orgOrgListRes, orgOrgDn)
pass


# create uplink
def createUplink(inUcsmHost, fabricEthLanEpStr):
        """Configures uplink port in UCS Manager."""
        logging.debug('create uplink')
        fabricEthLanEpList = ast.literal_eval(fabricEthLanEpStr)

        pDn = "fabric/lan/"+fabricEthLanEpList[FabricEthLanEp.SWITCH_ID]
        fabricEthLanEpDn = pDn + "phys-slot-" + fabricEthLanEpList[FabricEthLanEp.SLOT_ID] +"-port-" + fabricEthLanEpList[FabricEthLanEp.PORT_ID]

        #
        addObjectToUcs(inUcsmHost, pDn, FabricEthLan.ClassId(), FabricEthLanEp.ClassId(), fabricEthLanEpList, fabricEthLanEpDn)
pass

# configures server-pool requirement for SP.
def createLsRequirement(inUcsmHost, lsRequirementStr):
        """Configures ServerPool for ServiceProfile Template in UCS Manager."""
        logging.debug('create LsRequirement')
        lsRequirementList = ast.literal_eval(lsRequirementStr)

	lsRequirementListRes = { LsRequirement.NAME:lsRequirementList[LsRequirement.NAME],
				 LsRequirement.QUALIFIER:lsRequirementList[LsRequirement.QUALIFIER]
                               }

        pDn = lsRequirementList['SrcTemplDn']
        lsRequirementDn = pDn + "/pn-req" 

        #
	inUcsmHost.debug = True
        addObjectToUcs(inUcsmHost, pDn, LsServer.ClassId(), LsRequirement.ClassId(), lsRequirementListRes, lsRequirementDn)
pass

def createStorageLocalDiskConfigPolicy(inUcsmHost, storageLocalDiskConfigPolicyStr):
	"""Configures the LocalDiskConfiguration Policies."""
	logging.debug('create StorageLocalDiskConfigPolicy')
	storageLocalDiskConfigPolicyList = ast.literal_eval(storageLocalDiskConfigPolicyStr)
	pDn = 'org-root'
	storageLocalDiskConfigPolicyDn  = pDn + "/local-disk-config-" + storageLocalDiskConfigPolicyList[StorageLocalDiskConfigPolicy.NAME]

	inUcsmHost.debug = True
	addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), StorageLocalDiskConfigPolicy.ClassId(), storageLocalDiskConfigPolicyList, storageLocalDiskConfigPolicyDn)

pass


def getClassId(lsbootPolicyList):
        """ returns the classId based on the type"""
	lClassId = 'None'

        if 'vm' == lsbootPolicyList['type']:
                lClassId = LsbootVirtualMedia.ClassId()
        elif 'storage' == lsbootPolicyList['type']:
                lClassId = LsbootStorage.ClassId()
        elif 'lan' == lsbootPolicyList['type']:
                lClassId = LsbootLan.ClassId()
        pass
	logging.debug('ClassId'+lClassId)
	return lClassId
pass


def createLsbootPolicy(inUcsmHost, lsbootPolicyStr):
        """Configures the LsbootPolicy policies."""
        logging.debug('create LsbootPolicy ' + lsbootPolicyStr)
        lsbootPolicyList = ast.literal_eval(lsbootPolicyStr)

        pDn = lsbootPolicyList['TargetOrg']

        lsbootPolicyDn = pDn + "/boot-policy-" + lsbootPolicyList[LsbootPolicy.NAME]
        inUcsmHost.debug = True
        lsbootPolicyResList = {
                                LsbootPolicy.NAME: lsbootPolicyList[LsbootPolicy.NAME], \
                                LsbootPolicy.PURPOSE: lsbootPolicyList[LsbootPolicy.PURPOSE], \
                                LsbootPolicy.REBOOT_ON_UPDATE: lsbootPolicyList[LsbootPolicy.REBOOT_ON_UPDATE], \
                                LsbootPolicy.ENFORCE_VNIC_NAME: lsbootPolicyList[LsbootPolicy.ENFORCE_VNIC_NAME], \
                                LsbootPolicy.DESCR: lsbootPolicyList[LsbootPolicy.DESCR]
                               }

        addObjectToUcs(inUcsmHost, pDn, OrgOrg.ClassId(), LsbootPolicy.ClassId(), lsbootPolicyResList, lsbootPolicyDn)

        # VirtualMedia read-only Access
        if 'vm-ro' in lsbootPolicyList.keys():
                rnPrefix = lsbootPolicyList['vm-ro']['Access'] + "-" + lsbootPolicyList['vm-ro']['Type']
                lsbootVirtualMediaDn = lsbootPolicyDn + "/" + rnPrefix
                lsbootVirtualMediaList = lsbootPolicyList['vm-ro'] 
        	addObjectToUcs(inUcsmHost, lsbootPolicyDn, LsbootPolicy.ClassId(), LsbootVirtualMedia.ClassId(), lsbootVirtualMediaList, lsbootVirtualMediaDn)
	pass

        # LAN or PXE Boot option
        if 'lan' in lsbootPolicyList.keys():
                rnPrefix = lsbootPolicyList['lan']['Type']
                lsbootLanDn = lsbootPolicyDn + "/" + rnPrefix
		lsbootLanImagePathList = lsbootPolicyList['lan'].pop('ImagePath')
                lsbootLanList = lsbootPolicyList['lan']
	        addObjectToUcs(inUcsmHost, lsbootPolicyDn, LsbootPolicy.ClassId(), LsbootLan.ClassId(), lsbootLanList, lsbootLanDn)
		#ImagePath
		lsbootLanImagePathDn = lsbootLanDn + "/path-" + lsbootLanImagePathList['Type']
		addObjectToUcs(inUcsmHost, lsbootLanDn, LsbootLan.ClassId(), LsbootLanImagePath.ClassId(), lsbootLanImagePathList, lsbootLanImagePathDn)

	pass

        # Storage/LocalStorage
        if 'storage' in lsbootPolicyList.keys():

                rnPrefix = lsbootPolicyList['storage']['Type']

                lsbootStorageDn = lsbootPolicyDn + "/" + rnPrefix
                lsbootStorageList = lsbootPolicyList['storage'] 
        	addObjectToUcs(inUcsmHost, lsbootPolicyDn, LsbootPolicy.ClassId(), LsbootStorage.ClassId(), lsbootStorageList, lsbootStorageDn)
		lsbootLocalStorageDn = lsbootStorageDn + "/" + "local-storage"
		addObjectToUcs(inUcsmHost, lsbootStorageDn, LsbootStorage.ClassId(), LsbootLocalStorage.ClassId(), {}, lsbootLocalStorageDn)

	pass

        # VirtualMedia read-write Access
        if 'vm-rw' in lsbootPolicyList.keys():
                rnPrefix = lsbootPolicyList['vm-rw']['Access'] + "-" + lsbootPolicyList['vm-rw']['Type']
                lsbootVirtualMediaDn = lsbootPolicyDn + "/" + rnPrefix
                lsbootVirtualMediaList = lsbootPolicyList['vm-rw']
        	addObjectToUcs(inUcsmHost, lsbootPolicyDn, LsbootPolicy.ClassId(), LsbootVirtualMedia.ClassId(), lsbootVirtualMediaList, lsbootVirtualMediaDn)
	pass
pass
