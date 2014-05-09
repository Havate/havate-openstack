import types
from xml.dom.minidom import *
from MoMeta import _VersionMeta,_ManagedObjectMeta
from MethodMeta import _MethodFactoryMeta
from UcsHandle import *
from Constants import *

externalMethodAttrs = [ 'errorCode', 'errorDescr', 'invocationResult', 'response']

def str_to_class(s):
	if s in globals() and isinstance(globals()[s], types.ClassType):
		return globals()[s]
	return None

class UcsBase:
	WRITE_XML_OPTION_ALL = 0
	WRITE_XML_OPTION_ALLCONFIG = 1
	WRITE_XML_OPTION_DIRTY = 2

	def __init__(self, classId):
		self.classId = classId
		self.child = []
		self.handle = None
		self.dirtyMask = None

	def ToXml(self, options):
		w = xml.dom.minidom.Document()
		w.appendChild(self.WriteXml(w, options))
		return w.toxml()

	def GetHandle(self):
		return self.handle

	def SetHandle(self, handle):
		self.handle = handle

	def GetChild(self):
		return self.child

	def GetChildCount(self):
		return len(self.child)

	def childWriteXml(self, w, option):
		ch = []
		for c in self.child:
			ch.append(c.WriteXml(w,option))
		return ch

	def RemoveChild(self, obj):
		self.child.remove(obj)

	def childIsDirty(self):
		for c in self.child:
			if c.IsDirty():
				return True
		return False

	def childMarkClean(self):
		for c in self.child:
			c.MarkClean()

	def MarkClean(self):
		self.dirtyMask = 0

	def IsDirty(self):
		return self.childIsDirty()

	def WriteObject(self):
		for c in self.child:
			if c != None:
				c.WriteObject()
	
	def Clone(self):
		import copy
		return copy.deepcopy(self)

#	def __copy__(self):
#		return self
#
	def __deepcopy__(self,memo):
		import copy
		clone = copy.copy(self)
		cloneChild = []
		for c in clone.child:
			cloneChild.append(copy.deepcopy(c))
		clone.child = cloneChild
		return clone


class AbstractFilter(UcsBase):
	pass

class ManagedObject(UcsBase):
	DUMMYDIRTY = "0x1L"
	
	def __init__(self, classId):

		unknownMo = False
		# make classId case insensitive
		metaClassId = UcsUtils.FindClassIdInMoMetaIgnoreCase(classId)
		if (metaClassId == None):
			self.classId = classId
			self.propMoMeta = UcsMoMeta(classId, classId, "", "", "InputOutput", ManagedObject.DUMMYDIRTY, [], [], [], [])
			unknownMo = True
		else:
			self.classId = metaClassId
			self.propMoMeta = UcsUtils.GetUcsPropertyMeta(self.classId, "Meta")

		""" __init__ of the UcsBase class """
		UcsBase.__init__(self, self.classId)

		self.XtraProperty = {}

		""" instantiate class variables """
		if (not unknownMo):
			for prop in _ManagedObjectMeta[self.classId]:
				if prop != "Meta":
					self.__dict__[prop] = None

		if unknownMo:
			self.MarkDirty()
		else:
			self.MarkClean()

	def FilterVersion(self, version):
		if((self.propMoMeta != None) and (version != None)):
			if self.__dict__.has_key("XtraProperty"):
				self._excludePropList.append("XtraProperty")

			for prop in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId):
				propMeta = UcsUtils.IsPropertyInMetaIgnoreCase(self.classId, prop)
				if((propMeta == None) or (version < propMeta.version) or (propMeta.access == UcsPropertyMeta.Internal)):
					self._excludePropList.append(prop)

		for c in self.GetChild():
			c.FilterVersion(version)

	def setattr(self, key, value):
		if (UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId) != None):
			if (key in _ManagedObjectMeta[self.classId].keys()):
				propMeta = UcsUtils.GetUcsPropertyMeta(self.classId, key)
				
				if (propMeta.ValidatePropertyValue(value) == False):
					#print "Validation Failure"
					return False

				if (propMeta.mask != None):
					self.dirtyMask |= propMeta.mask

				self.__dict__[key] = value
			else:
				self.__dict__['XtraProperty'][key] = value
		else:
			""" no such property """
			self.__dict__['XtraProperty'][UcsUtils.WordU(key)] = value
			#return None

	def __setattr__(self, key, value):
		if ((key == "classId") or (UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId) == None) or (key not in _ManagedObjectMeta[self.classId].keys())):
			self.__dict__[key] = value
			return
		
		return self.setattr(key, value)

	def getattr(self, key):
		if ((key == "classId") and (self.__dict__.has_key(key))):
			return self.__dict__[key]

		if UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId):
			if self.__dict__.has_key(key):
				if key in _ManagedObjectMeta[self.classId].keys():
					""" property exists """
					return self.__dict__[key]
			else:
				if self.__dict__.has_key('XtraProperty'):
					if self.__dict__['XtraProperty'].has_key(key):
						return self.__dict__['XtraProperty'][UcsUtils.WordU(key)]
					else:
						raise AttributeError(key)
				else:
					print "No XtraProperty in mo:", self.classId, " key:", key
		else:
			""" property does not exist """
			if self.__dict__['XtraProperty'].has_key(key):
				return self.__dict__['XtraProperty'][UcsUtils.WordU(key)]
			else:
				raise AttributeError(key)

	def __getattr__(self, key):
		return self.getattr(key)

	def AddChild(self, mo):
		self.child.append(mo)

	def MarkDirty(self):
		if ((UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId) == None) and (not self.IsDirty())):
			self.dirtyMask = ManagedObject.DUMMYDIRTY
		else:
			self.dirtyMask = self.propMoMeta.mask

	def IsDirty(self):
		return ((self.dirtyMask != 0) or (self.childIsDirty()))
		
	def MakeRn(self):
		rnPattern = self.propMoMeta.rn
		for prop in re.findall("\[([^\]]*)\]",rnPattern):
			if prop in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId):
				if (self.getattr(prop) != None):
					rnPattern = re.sub('\[%s\]' % prop,'%s' % self.getattr(prop), rnPattern)
				else:
					raise Exception('Property "%s" was None in MakeRn' %prop)
			else:
				raise Exception('Property "%s" was not found in MakeRn arguments' %prop)
		#print rnPattern
		return rnPattern

	def WriteXml(self, w, option, elementName=None):
		if (option == WriteXmlOption.Dirty and not self.IsDirty()):
			return
		if elementName == None:
			x = w.createElement(self.propMoMeta.xmlAttribute)
		else:
			x = w.createElement(elementName)
		if UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId)!=None:
			for at in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId):
				atMeta = UcsUtils.GetUcsPropertyMeta(self.classId, at)
				if (atMeta.access == UcsPropertyMeta.Internal):
					continue
				elif ((option != WriteXmlOption.Dirty) or ((atMeta.mask != None) and (self.dirtyMask & atMeta.mask) != 0)):
					if (getattr(self, at) != None):
						x.setAttribute(atMeta.xmlAttribute,getattr(self, at))
		#Adding XtraProperties from object into Xml query document
		for xtraProp in self.__dict__['XtraProperty'].keys():
			x.setAttribute(UcsUtils.WordL(xtraProp),self.__dict__['XtraProperty'][xtraProp])
		x_child = self.childWriteXml(w, option)
		for xc in x_child:
			if (xc != None):
				x.appendChild(xc)
		return x

	def LoadFromXml(self, node, handle):
		self.SetHandle(handle)
		if node.hasAttributes():
			attributes = node._get_attributes()
			attCount = attributes._get_length()
			for i in range(attCount):
				attNode = attributes.item(i)
				attr = UcsUtils.WordU(attNode._get_name())
				if (UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId) != None):
					if (attr in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId)):
						self.setattr(attr, str(attNode.nodeValue))
					else:
						self.setattr(UcsUtils.WordU(attr), str(attNode.nodeValue))
				else:
					self.setattr(UcsUtils.WordU(attr), str(attNode.nodeValue))

		if(node.hasChildNodes()):
			childList = node._get_childNodes()
			childCount = childList._get_length()
			for i in range(childCount):
				childNode = childList.item(i)
				if (childNode.nodeType != Node.ELEMENT_NODE):
					continue

				if childNode.localName in self.propMoMeta.fieldNames:
					#.LoadFromXml(childNode, handle)
					pass
				#TODO: Need code analysis.
				#if childNode.localName in self.propMoMeta.childFieldNames:
				c = ManagedObject(UcsUtils.WordU(childNode.localName))
				self.child.append(c)
				c.LoadFromXml(childNode, handle)
	def __str__(self):
		from UcsBase import _write_mo
		return _write_mo(self)

class ExternalMethod(UcsBase):

	def __init__(self, classId):

		# make classId case insensitive
		metaClassId = UcsUtils.FindClassIdInMethodMetaIgnoreCase(classId)
		if (metaClassId == None):
			raise Exception("Invalid class Id %s" % classId)
		else:
			classId = metaClassId

		""" __init__ of the UcsBase class """
		UcsBase.__init__(self, classId)

		self.classId = classId
		self.propMoMeta = UcsUtils.GetUcsMethodMeta(self.classId, "Meta")

		""" instantiate class variables """
		for prop in _MethodFactoryMeta[classId]:
			if prop != "Meta":
				self.__dict__[prop] = None

		self.errorCode = 0
		self.errorDescr = None
		self.invocationResult = None
		self.response = None

		self.MarkClean()

	def AddChild(self, mo):
		self.child.append(mo)

	def setattr(self, key, value):
		if key in _MethodFactoryMeta[self.classId].keys():
			self.__dict__[key] = value
		elif key == 'errorCode':
			self.errorCode = value
		elif key == 'errorDescr':
			self.errorDescr = value
		elif key == 'invocationResult':
			self.invocationResult = value
		elif key == 'response':
			self.response = value
		else:
			""" no such property """
			#print "No such property ClassId: %s Property:%s" %(self.classId, key)
			return None

	def getattr(self, key):
		if key in _MethodFactoryMeta[self.classId].keys():
			""" property exists """
			return self.__dict__[key]
		else:
			""" property does not exist """
			return None

	def getErrorResponse(self, errorCode, errorDescr):
		self.errorCode = errorCode
		self.errorDescr = errorDescr
		self.response = "yes"
		return self

	def WriteXml(self, w, option, elementName=None):
		if elementName == None:
			x = w.createElement(self.propMoMeta.xmlAttribute)
		else:
			x = w.createElement(elementName)
		for at in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId):
			atMeta = UcsUtils.GetUcsMethodMeta(self.classId, at)
			if (atMeta.io == "Output"):
				continue
			if atMeta.isComplexType:
				if (getattr(self, at) != None):
					x.appendChild(self.__dict__[at].WriteXml(w, option, UcsUtils.WordL(at)))
			elif (getattr(self, at) != None):
				x.setAttribute(atMeta.xmlAttribute,getattr(self, at))
		x_child = self.childWriteXml(w, option)
		for xc in x_child:
			if (xc != None):
				x.appendChild(xc)
		return x

	def LoadFromXml(self, node, handle):
		from Ucs import ClassFactory
		self.SetHandle(handle)
		if node.hasAttributes():
			attributes = node._get_attributes()
			attCount = attributes._get_length()
			for i in range(attCount):
				attNode = attributes.item(i)
				attr = UcsUtils.WordU(attNode._get_name())
				if (attr in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId)):
					atMeta = UcsUtils.GetUcsMethodMeta(self.classId, attr)
					if ((atMeta.io == "Input") or (atMeta.isComplexType)):
						continue
					self.setattr(attr, str(attNode.nodeValue))
				elif (attNode._get_name() in externalMethodAttrs):
					self.setattr(attNode._get_name(), str(attNode.nodeValue))

		if(node.hasChildNodes()):
			childList = node._get_childNodes()
			childCount = childList._get_length()
			for i in range(childCount):
				childNode = childList.item(i)
				if (childNode.nodeType != Node.ELEMENT_NODE):
					continue

				cln = UcsUtils.WordU(childNode.localName)
				if cln in UcsUtils.GetUcsPropertyMetaAttributeList(self.classId):
					atMeta = UcsUtils.GetUcsMethodMeta(self.classId, cln)
					if ((atMeta.io == "Output") and (atMeta.isComplexType)):
						c = ClassFactory(atMeta.fieldType)
						if (c != None):
							self.setattr(cln, c)
							c.LoadFromXml(childNode, handle)

class UcsUtils:
	@staticmethod
	def IsValidClassId(classId):
		if ((classId in _ManagedObjectMeta.keys()) or (classId in _MethodFactoryMeta.keys())):
			return True
		return False

	@staticmethod
	def GetUcsPropertyMeta(classId, key):
		if classId in _ManagedObjectMeta.keys():
			if key in _ManagedObjectMeta[classId].keys():
				return _ManagedObjectMeta[classId][key]
		return None

	@staticmethod
	def GetUcsMethodMeta(classId, key):
		if classId in _MethodFactoryMeta.keys():
			if key in _MethodFactoryMeta[classId].keys():
				return _MethodFactoryMeta[classId][key]
		return None

	@staticmethod
	def GetUcsPropertyMetaAttributeList(classId):
		if classId in _ManagedObjectMeta.keys():
			attrList = _ManagedObjectMeta[classId].keys()
			attrList.remove("Meta")
			return attrList
		if classId in _MethodFactoryMeta.keys():
			attrList = _MethodFactoryMeta[classId].keys()
			attrList.remove("Meta")
			return attrList

		#If the case of classId is not as in Meta
		nci = UcsUtils.FindClassIdInMoMetaIgnoreCase(classId)
		if (nci != None):
			attrList = _ManagedObjectMeta[nci].keys()
			attrList.remove("Meta")
			return attrList

		nci = UcsUtils.FindClassIdInMethodMetaIgnoreCase(classId)
		if (nci != None):
			attrList = _MethodFactoryMeta[nci].keys()
			attrList.remove("Meta")
			return attrList

		return None

	@staticmethod
	def IsPropertyInMetaIgnoreCase(classId, key):
		if classId in _ManagedObjectMeta.keys():
			for prop in _ManagedObjectMeta[classId].keys():
				if (prop.lower() == key.lower()):
					return _ManagedObjectMeta[classId][prop]
		if classId in _MethodFactoryMeta.keys():
			for prop in _MethodFactoryMeta[classId].keys():
				if (prop.lower() == key.lower()):
					return _MethodFactoryMeta[classId][prop]
		return None

	@staticmethod
	def FindClassIdInMoMetaIgnoreCase(classId):
		for key in _ManagedObjectMeta.keys():
			if (key.lower() == classId.lower()):
				return key
		return None

	@staticmethod
	def FindClassIdInMethodMetaIgnoreCase(classId):
		for key in _MethodFactoryMeta.keys():
			if (key.lower() == classId.lower()):
				return key
		return None

	@staticmethod
	def HandleFilterMaxComponentLimit(handle, lfilter):
		from Ucs import AndFilter,OrFilter,AbstractFilter
		maxComponents = 10
		if ((lfilter == None) or (lfilter.GetChildCount() <= maxComponents)):
			return lfilter

		if ((not(isinstance(lfilter,AndFilter))) and (not(isinstance(lfilter,OrFilter)))):
			return lfilter
		
		resultFilter = None
		if (isinstance(lfilter, AndFilter) == True):
			parentFilter = AndFilter()
			childFilter = AndFilter()
			parentFilter.AddChild(childFilter)
			for cf in lfilter.GetChild():
				if (isinstance(cf, AbstractFilter) == True):
					if (childFilter.GetChildCount() == maxComponents):
						childFilter = AndFilter()
						parentFilter.AddChild(childFilter)
					childFilter.AddChild(cf)
			resultFilter = parentFilter
		else:
			parentFilter = OrFilter()
			childFilter = OrFilter()
			parentFilter.AddChild(childFilter)
			for cf in lfilter.GetChild():
				if (isinstance(cf, AbstractFilter) == True):
					if (childFilter.GetChildCount() == maxComponents):
						childFilter = OrFilter()
						parentFilter.AddChild(childFilter)
					childFilter.AddChild(cf)
			resultFilter = parentFilter
		return UcsUtils.HandleFilterMaxComponentLimit(handle, resultFilter)

	@staticmethod
	def WordL(word):
		return (word[0].lower() + word[1:])

	@staticmethod
	def WordU(word):
		return (word[0].upper() + word[1:])

	@staticmethod
	def MakeDn(rnArray):
		return '/'.join(rnArray)
	
	@staticmethod
	def CheckRegistryKey(javaKey):
		from _winreg import ConnectRegistry, HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx
		path = None
		try:
			aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
			rk = OpenKey(aReg, javaKey)
			for i in range(1024):
				currentVersion = QueryValueEx(rk, "CurrentVersion")            
				if currentVersion!= None:
					key  =OpenKey(rk,currentVersion[0])
					if key != None:
						path = QueryValueEx(key, "JavaHome")
						return path[0]
		except Exception, err:
			WriteUcsWarning("Not able to access registry.")
			return None

	@staticmethod
	def GetJavaInstallationPath():
		import os, platform
		
		# Get JavaPath for Ubuntu
		#if os.name == "posix":
		if platform.system() == "Linux":
			path = os.environ.get('JAVA_HOME')
			if not path:
				WriteUcsWarning("Please make sure JAVA is installed and variable JAVA_HOME is set properly.")
				return None
			else:
				path = os.path.join(path, 'bin')
				path = os.path.join(path, 'javaws')
				if not os.path.exists(path):
					WriteUcsWarning("javaws is not installed on System.")
					return None
				else:
					return path
		
		# Get JavaPath for Windows
		#elif os.name == "nt":
		elif platform.system() == "Windows" or platform.system() == "Microsoft":
			
			path = os.environ.get('JAVA_HOME')
			
			if path == None:
				path = UcsUtils.CheckRegistryKey(r"SOFTWARE\\JavaSoft\\Java Runtime Environment\\")
			
			if path == None:#Check for 32 bit Java on 64 bit machine.
				path = UcsUtils.CheckRegistryKey(r"SOFTWARE\\Wow6432Node\\JavaSoft\\Java Runtime Environment")
			
			if not path:
				WriteUcsWarning("Please make sure JAVA is installed.")
				return None
			else:
				path = os.path.join(path, 'bin')
				path = os.path.join(path, 'javaws.exe')
				if not os.path.exists(path):
					WriteUcsWarning("javaws.exe is not installed on System.")
					return None
				else:
					return path
		elif platform.system() == "Darwin":
			path = os.environ.get('JAVA_HOME')
			if path == None:
				WriteUcsWarning("Please make sure JAVA is installed and variable JAVA_HOME is set properly.")
				return None
			else:
				path = os.path.join(path, 'bin')
				path = os.path.join(path, 'javaws')
				if not os.path.exists(path):
					WriteUcsWarning("javaws is not installed on system.")
					return None
				else:
					return path
				pass
			pass
		pass
				
	@staticmethod
	def DownloadFile(hUcs, source, destination):
		import urllib2
		from sys import stdout
		from time import sleep
		
		httpAddress = "%s/%s" %(hUcs.Uri(), source)
		file_name = httpAddress.split('/')[-1]
		
		req = urllib2.Request(httpAddress)#send the new url with the cookie.
		req.add_header('Cookie','ucsm-cookie=%s' %(hUcs._cookie))
		res = urllib2.urlopen(req)
		
		meta = res.info()
		file_size = int(meta.getheaders("Content-Length")[0])
		print "Downloading: %s Bytes: %s" % (file_name, file_size)
		
		f = open(destination, 'wb')
		file_size_dl = 0
		block_sz = 8192
		while True:
			rBuffer = res.read(block_sz)
			if not rBuffer:
				break

			file_size_dl += len(rBuffer)
			f.write(rBuffer)
			status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
			status = status + chr(8)*(len(status)+1)
			stdout.write("\r%s" % status)
			stdout.flush()
			#print status
	
		f.close()
		
	
	@staticmethod
	def GetSyncMoConfigFilePath():
		return os.path.join(os.path.join(os.path.dirname(__file__),"resources"),"SyncMoConfig.xml")
		
	@staticmethod
	def GetSyncMoConfig(ConfigDoc):
		moConfigMap = {}
		configList = ConfigDoc.getElementsByTagName("mo")
		
		for moConfigNode in configList:
			classId=None
			noun=None
			version=None
			actionVersion=None
			action=None
			ignoreReason=None
			status=None
			excludeList=None
			
			if moConfigNode.hasAttribute("classid"):
				classId = moConfigNode.getAttribute("classid")
			
			if moConfigNode.hasAttribute("noun"):
				noun = moConfigNode.getAttribute("noun")
				
			if moConfigNode.hasAttribute("version"):
				version = moConfigNode.getAttribute("version")
				
			if moConfigNode.hasAttribute("actionVersion"):
				actionVersion = moConfigNode.getAttribute("actionVersion")
				
			if moConfigNode.hasAttribute("action"):
				action = moConfigNode.getAttribute("action")
				
			if moConfigNode.hasAttribute("ignoreReason"):
				ignoreReason = moConfigNode.getAttribute("ignoreReason")
				
			if moConfigNode.hasAttribute("status"):
				status = moConfigNode.getAttribute("status")
				
			if moConfigNode.hasAttribute("excludeList"):
				excludeList = moConfigNode.getAttribute("excludeList")
			
			# SyncMoConfig Object
			moConfig = None
			
			if classId:
				moConfig = SyncMoConfig(classId, noun, version, actionVersion, action, ignoreReason, status, excludeList)
			
			if moConfig:
				if classId in moConfigMap:
					moConfigMap[classId] = moConfig
				else:
					moConfigList = []
					moConfigList.append(moConfig)
					moConfigMap[classId] = moConfigList
			
		return moConfigMap		
		

def _write_mo(mo):
	from UcsBase import UcsUtils
	classNotFound = False
	if(UcsUtils.FindClassIdInMoMetaIgnoreCase(mo.classId) == None):
		classNotFound = True

	tabsize = 8
	outstr = "\n"
	if classNotFound:
		outstr += "Managed Object\t\t\t:\t" + str(UcsUtils.WordU(mo.classId)) + "\n"
	else:
		outstr += "Managed Object\t\t\t:\t" + str(mo.propMoMeta.name) + "\n"
	outstr += "-"*len("Managed Object") + "\n"
	if(not classNotFound):
		for prop in UcsUtils.GetUcsPropertyMetaAttributeList(mo.propMoMeta.name):
			propMeta = UcsUtils.GetUcsPropertyMeta(mo.propMoMeta.name,prop)
			if (propMeta.access == UcsPropertyMeta.Internal):
				continue
			val = mo.getattr(prop)
			#if val != None and val != "":
			outstr += str(prop).ljust(tabsize*4) + ':' + str(val) + "\n"
	else:
		for prop in mo.__dict__.keys():
			if (prop in ['classId', 'XtraProperty', 'handle', 'propMoMeta', 'dirtyMask', 'child']):
				continue
			val = mo.__dict__[prop]
			outstr += str(UcsUtils.WordU(prop)).ljust(tabsize*4) + ':' + str(val) + "\n"
	if mo.__dict__.has_key('XtraProperty'):
		for xtraProp in mo.__dict__['XtraProperty'].keys():
			outstr += '[X]' + str(UcsUtils.WordU(xtraProp)).ljust(tabsize*4) + ':' + str(mo.__dict__['XtraProperty'][xtraProp]) + "\n"
	outstr += "\n"
	return outstr 

def WriteMoDiff(diffObj):
	tabsize = 8
	print str(diffObj.Dn).ljust(tabsize*10),str(diffObj.InputObject.propMoMeta.name).ljust(tabsize*4),str(diffObj.SideIndicator).ljust(tabsize*3),str(diffObj.DiffProperty)

def WriteObject(moList):
	from Ucs import Dn
	from UcsHandle import UcsMoDiff

	tabsize = 8
	if (isinstance(moList, _GenericMO) == True):
		print str(moList)
	elif (isinstance(moList, ExternalMethod) == True):
		if (hasattr(moList, "OutConfigs") == True):
			for child in moList.OutConfigs.GetChild():
				if (isinstance(child, ManagedObject) == True):
					WriteObject(child)
	elif (isinstance(moList, ManagedObject) == True):
		print str(_write_mo(moList))
	elif ((isinstance(moList, list) == True) and (len(moList) > 0)):
		if (isinstance(moList[0],UcsMoDiff)):
			print "Dn".ljust(tabsize*10),"InputObject".ljust(tabsize*4),"SideIndicator".ljust(tabsize*3),"DiffProperty"
			print "--".ljust(tabsize*10),"-----------".ljust(tabsize*4),"-------------".ljust(tabsize*3),"------------"
		for mo in moList:
			if (isinstance(mo, ManagedObject) == True):
				print str(_write_mo(mo))
			elif(isinstance(mo, Dn) == True):
				print mo.getattr("value")
			elif(isinstance(mo, UcsMoDiff) == True):
				WriteMoDiff(mo)

def WriteUcsWarning(string):
	print string

class GenericMO(ManagedObject):
	def __init__(self, mo, option):
		ManagedObject.__init__(self, mo.classId)
		self._excludePropList = []
		w = xml.dom.minidom.Document()
		w.appendChild(mo.WriteXml(w, option))

		doc = parseString(w.toxml())
		self.LoadFromXml(doc.childNodes[0], mo.handle)


class _GenericMO(ManagedObject):
	def __init__(self, loadXml=None, mo=None, option=WriteXmlOption.AllConfig):
		ManagedObject.__init__(self,"GMO")
		self.dn = None
		self.rn = None
		self.properties = {}
		self.loadXml = loadXml
		self.mo = mo
		self.option = option
		
		if loadXml:
			self.GetRootNode(loadXml)
		
		if mo:
			self.FromManagedObject()
		
	def GetRootNode(self,xmlString):
		_doc = xml.dom.minidom.parseString(xmlString)
		rootNode = _doc.documentElement
		self.LoadFromXml(rootNode)
		
	def GetAttribute(self, attr):
		if attr in self.properties.keys():
			return self.properties[attr]
		return None
	
	def WriteToAttributes(self,node):
		if node.hasAttributes():
			for _attr, _val in node.attributes.items():
				self.properties[_attr] = _val
			
	def LoadFromXml(self,node):
		import os
		self.classId = node.localName
		metaClassId = UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId)

		if metaClassId:
			self.classId = metaClassId
		
		if node.hasAttribute(NamingPropertyId.DN):
			self.dn = node.getAttribute(NamingPropertyId.DN)
		
		if self.dn:
			self.rn = os.path.basename(self.dn)
		
		# Write the attribute and value to dictionary properties, as it is .
		self.WriteToAttributes(node)
		
		# Run the LoadFromXml for each childNode recursively and populate child list too.
		if(node.hasChildNodes()):
			childList = node._get_childNodes()
			childCount = childList._get_length()
			for i in range(childCount):
				childNode = childList.item(i)
				if (childNode.nodeType != Node.ELEMENT_NODE):
					continue
				c = _GenericMO()
				self.child.append(c)
				c.LoadFromXml(childNode)
		
	def WriteXml(self, w, option, elementName=None):
		if elementName == None:
			x = w.createElement(self.classId)
		else:
			x = w.createElement(elementName)
			
		for prop in self.__dict__['properties'].keys():
			x.setAttribute(UcsUtils.WordL(prop),self.__dict__['properties'][prop])
		x_child = self.childWriteXml(w, option)
		for xc in x_child:
			if (xc != None):
				x.appendChild(xc)
		return x
	 
	def ToManagedObject(self):
		from Ucs import ClassFactory 
	
		cln = UcsUtils.WordU(self.classId)
		mo = ClassFactory(cln)
		if mo and (isinstance(mo, ManagedObject) == True):
			metaClassId = UcsUtils.FindClassIdInMoMetaIgnoreCase(self.classId)
			for property in self.properties.keys():
				if UcsUtils.WordU(property) in UcsUtils.GetUcsPropertyMetaAttributeList(metaClassId):
					mo.setattr(UcsUtils.WordU(property), self.properties[property])
				else:
					WriteUcsWarning("Property %s Not Exist in MO %s" %(UcsUtils.WordU(property), metaClassId))
			
			if len(self.child):
				for ch in self.child:
					moch = ch.ToManagedObject()
					mo.child.append(moch)
			return mo
		else:
			return None
		
		
	def FromManagedObject(self):

		import os
		if (isinstance(self.mo, ManagedObject) == True):
			self.classId = self.mo.classId
			
			if self.mo.getattr('Dn'):
				self.dn = self.mo.getattr('Dn')
				
			if self.mo.getattr('Rn'):
				self.rn = self.mo.getattr('Rn')
			elif self.dn:
				self.rn = os.path.basename(self.dn)
				
			
			for property in UcsUtils.GetUcsPropertyMetaAttributeList(self.mo.classId):
				self.properties[property] = self.mo.getattr(property)
			
			if len(self.mo.child):
				for ch in self.mo.child:
					if not ch.getattr('Dn'):
						_Dn = self.mo.getattr('Dn') + "/" + ch.getattr('Rn')
						ch.setattr('Dn', _Dn)
					gmo = _GenericMO(mo=ch)
					self.child.append(gmo)

				
					
				
		
	def __str__(self):
		tabsize = 8
		if (isinstance(self, _GenericMO) == True):
			outStr = "\n"
			outStr +=  'classId'.ljust(tabsize*4) + ':' + str(self.__dict__['classId']) + "\n"
			outStr += 'dn'.ljust(tabsize*4) + ':' + str(self.__dict__['dn']) + "\n"
			outStr += 'rn'.ljust(tabsize*4) + ':' + str(self.__dict__['rn']) + "\n"
			for key, value in self.__dict__['properties'].items():
				outStr += key.ljust(tabsize*4) + ':' + str(value) + "\n"
			
			for ch in self.child:
				outStr += str(ch) + "\n"
				
			#print outStr
			return outStr
	
	def GetChildClassId(self,classId):
		childList = []
		for ch in self.child:
			if ch.classId.lower() == classId.lower():
				childList.append(ch)
		return childList
	
	def GetChild(self):
		return self.child
	
	
class SyncAction:
	statusChange = "STATUS_CHANGE"
	ignore = "IGNORE"
	none = "NONE"
		
	
class SyncMoConfig:
	
	classId = ""
	noun = ""
	version = None
	actionVersion = None
	action = ""
	ignoreReason = {}
	status = ""
	excludeList = []
	
	def __init__(self, classId, noun, version, actionVersion, action, ignoreReason, status, excludeList):
		self.classId = classId
		self.noun = noun
		
		if version:
			self.version = UcsVersion(version)
		else:
			self.version = None
		
		if actionVersion:
			self.actionVersion = UcsVersion(actionVersion)
		else:
			actionVersion = None
		
		self.status = status
		
		if (action.strip()).lower() == ("statusChange").lower():
			self.action = SyncAction.statusChange
		elif (action.strip()).lower() == ("ignore").lower():
			self.action = SyncAction.ignore
		else:
			self.action = SyncAction.none
		
		if excludeList:
			self.excludeList =  excludeList.split(",")
		else:
			self.excludeList = None
		
		irMap = {}	
		if ignoreReason and self.action == SyncAction.ignore:
			
			pairs = ignoreReason.strip().split(",")
			for pair in pairs:
				kv = pair.strip().split("=")
				if kv is None or len(kv) != 2:
					continue
				irMap[kv[0]] = kv[1]
		
		if irMap:
			self.ignoreReason = irMap
		
		
	def getClassid(self):
		return self.classId
	
	def getNoun(self):
		return self.noun
	
	def getVersion(self):
		return self.version
	
	def getActionVersion(self):
		return self.actionVersion
	
	def getAction(self):
		return self.action
	
	def getStatus(self):
		return self.status
	
	def getExcludeList(self):
		return self.excludeList
	
	def getIgnoreReason(self):
		return self.ignoreReason
		


		
		
		
				
			
		
		
		
				
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
