#!/usr/bin/python

import sys
import os
import ast
import time
import daemon
import logging
import argparse
import getpass
from UcsSdk import *
from SPConsumer import *


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Configures UCS Manager to add servers automatically to openstack cluster.',
			epilog="""This program takes configuration file which has the necessary policies, identities
                                  netowrk and port related information. It then configures these in UCSM, so that UCS Manager
                                  discovers servers and creates service-profiles. Later these servers will be added
                                  to openstack cluster.""")

        parser.add_argument('-i', '--ucsm', dest='hostname', help='UCS Manager hostname or ip address', required=True)
        parser.add_argument('-u', '--ucsm_user', dest='ucsm_user', help='Username to login to UCS Manager', required=True)
        parser.add_argument('-p', '--ucsm_password', dest='ucsm_password', help='Password to login to UCS Manager')
        parser.add_argument('-f', '--config-file', dest='conf_templ', help='Configuration file contains policies, identities, network and port info')
        parser.add_argument('-d', '--debug', dest='debug', type=bool, help='Enable logging', default=False)
        parser.add_argument('-l', '--listener-only', dest='listen_only', type=bool, help='Only listen for events, does not configures.', default=False)
        parser.add_argument('-o', '--configure-only', dest='configure_only', type=bool, help='Configures UCSM, does not listen for events.', default=False)
        parser.add_argument('-a', '--app-name', dest='app_name', help='Application name using this integration.', default=AppName.OPENSTACK)
        parser.add_argument('-e', '--ip-address', dest='ip_address', help='Starting ip-address.')
        parser.add_argument('-r', '--ip-range', dest='ip_range', help='ip-address range.')
        parser.add_argument('-s', '--cobbler_user', dest='cobbler_user', help='Username to login to Cobbler', default="")
        parser.add_argument('-w', '--cobbler_password', dest='cobbler_password', help='Password to login to Cobbler', default="")
                                #choices = [AppName.OPENSTACK, AppName.COBBLER, AppName.CLOUDSTACK], default=False)
        args = parser.parse_args()
        ucsm_conf_templ = args.conf_templ
        ucsm_conf_templ = args.conf_templ
        ucsm_debug = args.debug
        ucsm_listener_only = args.listen_only
        app_name = args.app_name
        cobbler_user = args.cobbler_user
        cobbler_password = args.cobbler_password
	ucsm_configure_only = args.configure_only
	
	ucsmHost = UcsmHost(args.hostname, args.ucsm_user, args.ucsm_password, args.conf_templ, args.debug)

	ucsConsumer = ServiceProfileConsumerFactory(app_name)

        if not ucsmHost.password:
                ucsmHost.password = getpass.getpass()

        if not ucsm_listener_only:
                logging.debug('configureUcsPolicies')
                ucsConsumer.configureUcsPolicies(ucsm_conf_templ, ucsmHost)
        pass


	if not ucsm_configure_only:
		logging.debug('retrieve existing inventory and start listener')
		ucsConsumer.retrieveUcsConfig(app_name, ucsmHost)
		ucsConsumer.startListener(ucsmHost, app_name, cobbler_user, cobbler_password)
	pass

pass
