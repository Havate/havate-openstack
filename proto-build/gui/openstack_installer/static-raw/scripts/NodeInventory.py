#!/usr/bin/env python

import sys
import yaml
import traceback
import argparse
import os
from UcsSdk import *


def getProcessorUnitInventory(inHandle, inComputeBlade):
    inFilter = FilterFilter()
    wcardFilter = WcardFilter()
    wcardFilter.Class = "processorUnit"
    wcardFilter.Property = "dn"
    wcardFilter.Value = "%s/" % inComputeBlade.Dn
    inFilter.AddChild(wcardFilter)

    processorUnits = inHandle.ConfigResolveClass(ProcessorUnit.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml=False)

    if processorUnits.errorCode == 0:
        yaml_processor_units = {}
        for processorUnit in processorUnits.OutConfigs.GetChild():
            yaml_processor_unit = {}
            yaml_processor_unit['arch'] = processorUnit.getattr(ProcessorUnit.ARCH)
            yaml_processor_unit['cores'] = processorUnit.getattr(ProcessorUnit.CORES)
            yaml_processor_unit['coresEnabled'] = processorUnit.getattr(ProcessorUnit.CORES_ENABLED)
            yaml_processor_unit['model'] = processorUnit.getattr(ProcessorUnit.MODEL)
            yaml_processor_unit['socketDesignation'] = processorUnit.getattr(ProcessorUnit.SOCKET_DESIGNATION)
            yaml_processor_unit['speed'] = processorUnit.getattr(ProcessorUnit.SPEED)
            yaml_processor_unit['stepping'] = processorUnit.getattr(ProcessorUnit.STEPPING)
            yaml_processor_unit['threads'] = processorUnit.getattr(ProcessorUnit.THREADS)
            yaml_processor_unit['vendor'] = processorUnit.getattr(ProcessorUnit.VENDOR)
            yaml_processor_units['AdaptorUnit%s' % (processorUnit.getattr(ProcessorUnit.ID))] = yaml_processor_unit
        pass
        return yaml_processor_units
    pass
    return
pass


def getMemoryInventory(inHandle, inComputeBlade):
    inFilter = FilterFilter()
    wcardFilter = WcardFilter()
    wcardFilter.Class = "memoryArray"
    wcardFilter.Property = "dn"
    wcardFilter.Value = "%s/" % inComputeBlade.Dn
    inFilter.AddChild(wcardFilter)

    memoryArrays = inHandle.ConfigResolveClass(MemoryArray.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml=False)

    if (memoryArrays.errorCode == 0):
        yaml_memory_arrays = {}
        for memoryArray in memoryArrays.OutConfigs.GetChild():
            memory_array_unit = {}
            memory_array_unit['cpuId'] = memoryArray.getattr(MemoryArray.CPU_ID)
            memory_array_unit['currCapacity'] = memoryArray.getattr(MemoryArray.CURR_CAPACITY)
            memory_array_unit['maxCapacity'] = memoryArray.getattr(MemoryArray.MAX_CAPACITY)
            memory_array_unit['populated'] = memoryArray.getattr(MemoryArray.POPULATED)
            yaml_memory_arrays['MemoryArray-%s' % (memoryArray.getattr(MemoryArray.ID))] = memory_array_unit
        pass
        return yaml_memory_arrays
    pass
    return
pass


def getStorageInventory(inHandle, inComputeBlade):
    inFilter = FilterFilter()
    wcardFilter = WcardFilter()
    wcardFilter.Class = "storageLocalDisk"
    wcardFilter.Property = "dn"
    wcardFilter.Value = "%s/" % inComputeBlade.Dn
    inFilter.AddChild(wcardFilter)

    storageLocalDisks = inHandle.ConfigResolveClass(StorageLocalDisk.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml=False)
    if (storageLocalDisks.errorCode == 0):
        yaml_storage_local_disks = {}
        for storageLocalDisk in storageLocalDisks.OutConfigs.GetChild():
            yaml_storage_local_disk = {}
            yaml_storage_local_disk['blockSize'] = storageLocalDisk.getattr(StorageLocalDisk.BLOCK_SIZE)
            yaml_storage_local_disk['connectionProtocol'] = storageLocalDisk.getattr(StorageLocalDisk.CONNECTION_PROTOCOL)
            yaml_storage_local_disk['model'] = storageLocalDisk.getattr(StorageLocalDisk.MODEL)
            yaml_storage_local_disk['numberOfBlocks'] = storageLocalDisk.getattr(StorageLocalDisk.NUMBER_OF_BLOCKS)
            yaml_storage_local_disk['presence'] = storageLocalDisk.getattr(StorageLocalDisk.PRESENCE)
            yaml_storage_local_disk['serial'] = storageLocalDisk.getattr(StorageLocalDisk.SERIAL)
            yaml_storage_local_disk['size'] = storageLocalDisk.getattr(StorageLocalDisk.SIZE)
            yaml_storage_local_disk['vendor'] = storageLocalDisk.getattr(StorageLocalDisk.VENDOR)
            yaml_storage_local_disks['StorageLocalDisk-%s' % (storageLocalDisk.getattr(StorageLocalDisk.ID))] = yaml_storage_local_disk
        pass
        return yaml_storage_local_disks
    pass
    return
pass


def getAdaptorInventory(inHandle, inComputeBlade):
    inFilter = FilterFilter()
    wcardFilter = WcardFilter()
    wcardFilter.Class = "adaptorUnit"
    wcardFilter.Property = "dn"
    wcardFilter.Value = "%s/" % inComputeBlade.Dn
    inFilter.AddChild(wcardFilter)

    adaptorUnits = inHandle.ConfigResolveClass(AdaptorUnit.ClassId(), inFilter, inHierarchical=YesOrNo.FALSE, dumpXml=False)
    if (adaptorUnits.errorCode == 0):
        yaml_adaptor_units = {}
        for adaptorUnit in adaptorUnits.OutConfigs.GetChild():
            yaml_adaptor_unit = {}
            yaml_adaptor_unit['baseMac'] = adaptorUnit.getattr(AdaptorUnit.BASE_MAC)
            yaml_adaptor_unit['model'] = adaptorUnit.getattr(AdaptorUnit.MODEL)
            yaml_adaptor_unit['partNumber'] = adaptorUnit.getattr(AdaptorUnit.PART_NUMBER)
            yaml_adaptor_unit['serial'] = adaptorUnit.getattr(AdaptorUnit.SERIAL)
            yaml_adaptor_unit['vendor'] = adaptorUnit.getattr(AdaptorUnit.VENDOR)
            yaml_adaptor_units['AdaptorUnit-%s' % (adaptorUnit.getattr(AdaptorUnit.ID))] = yaml_adaptor_unit
        pass
        return yaml_adaptor_units
    pass
    return
pass


def getNodeInventory(inUcsmHost, inUserName, inPassword):
    try:
        handle = UcsHandle()
        login = handle.Login(inUcsmHost, inUserName, inPassword)
        if login is False:
            print('Login Failed')
            sys.exit(0)
        pass

        computeNodes = {}

        equipmentChassis = handle.GetManagedObject(None, EquipmentChassis.ClassId(), None, dumpXml=False)

        for chassis in equipmentChassis:
            computeNodes['Chassis-%s' % (chassis.getattr(EquipmentChassis.ID))] = {}
        pass

        # Adding systems is common across integration applications.
        computeBlades = handle.GetManagedObject(None, ComputeBlade.ClassId(), None, dumpXml=False)
        for computeBlade in computeBlades:
            computeNode = {}
            computeNode['chassisID'] = computeBlade.getattr(ComputeBlade.CHASSIS_ID)
            computeNode['availableMemory'] = computeBlade.getattr(ComputeBlade.AVAILABLE_MEMORY)
            computeNode['numOfAdaptors'] = computeBlade.getattr(ComputeBlade.NUM_OF_ADAPTORS)
            computeNode['numOfCores'] = computeBlade.getattr(ComputeBlade.NUM_OF_CORES)
            computeNode['numOfCoresEnabled'] = computeBlade.getattr(ComputeBlade.NUM_OF_CORES_ENABLED)
            computeNode['numOfCpus'] = computeBlade.getattr(ComputeBlade.NUM_OF_CPUS)
            computeNode['numOfEthHostIfs'] = computeBlade.getattr(ComputeBlade.NUM_OF_ETH_HOST_IFS)
            computeNode['numOfFcHostIfs'] = computeBlade.getattr(ComputeBlade.NUM_OF_FC_HOST_IFS)
            computeNode['numOfThreads'] = computeBlade.getattr(ComputeBlade.NUM_OF_THREADS)
            computeNode['assignedToDn'] = computeBlade.getattr(ComputeBlade.ASSIGNED_TO_DN)

            # get cpu inventory
            processorUnits = getProcessorUnitInventory(handle, computeBlade)
            computeNode['ProcessorUnits'] = processorUnits

            # get memory inventory
            memoryArrays = getMemoryInventory(handle, computeBlade)
            computeNode['MemoryArray'] = memoryArrays

            # get HardDisk Inventory
            storageUnits = getStorageInventory(handle, computeBlade)
            computeNode['StorageUnits'] = storageUnits

            # get adaptor inventory
            adaptorUnits = getAdaptorInventory(handle, computeBlade)
            computeNode['AdaptorUnits'] = adaptorUnits

            chassis_str = 'Chassis-%s' % (computeBlade.getattr(ComputeBlade.CHASSIS_ID))
            blade_str = 'Blade-%s' % (computeBlade.getattr(ComputeBlade.SLOT_ID))
            computeNodes[chassis_str][blade_str] = computeNode
        pass
        # write inventory to file

        yaml_ucs_server_inventory_file = open((os.path.join(os.path.abspath(os.path.dirname(__file__)), './%s_inventory.yaml' % (inUcsmHost))), 'w')
        yaml.safe_dump(computeNodes, yaml_ucs_server_inventory_file, default_flow_style=False)
        yaml_ucs_server_inventory_file.close()
    except Exception as err:
        print "Exception in user code:"
        print '-'*60
        traceback.print_exc(file=sys.stdout)
        print '-'*60
        print('2Exception:' + str(err))
    pass
pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Retrieves server inventory from UCS Manager.',
        epilog="""This program retrieves server inventory along with processor, memory, storage, adaptor inventory."""
    )

    parser.add_argument('--ucsm', '-i', dest='hostname', help='UCS Manager hostname or ip address', required=True)
    parser.add_argument('--ucsm_user', '-u', dest='ucsm_user', help='Username to login to UCS Manager', required=True)
    parser.add_argument('--ucsm_password', '-p', dest='ucsm_password', help='Password to login to UCS Manager')

    args = parser.parse_args()

    getNodeInventory(args.hostname, args.ucsm_user, args.ucsm_password)

pass
