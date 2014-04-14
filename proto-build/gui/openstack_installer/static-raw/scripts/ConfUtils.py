from UcsSdk import *
import logging
from UcsUtils import *

#cobbler specific configuration variables
cobbler_server=''
cobbler_user=''
cobbler_password=''
cobbler_handle=0
cobbler_token=0

# ucs server details.
ucsm_hostname=""
ucsm_user=""
ucsm_password=""
ucsm_debug=False
ucsm_handle = UcsHandle()

#conf file contains policies to be configured in UCS Manager.
ucsm_conf_templ=""
app_name=""
ucsmHost=UcsmHost('','','','','')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(os.path.join( os.path.abspath(os.path.dirname(__file__)), 'ucs.log'))
logger.addHandler(fh)
