Havate for OpenStack
====================

These tools are intended to help:

1) configure Cisco UCS via UCSM to support multi-node system setup
2) enable the deployment of a Canonical Ubuntu based (debian model) Linux environment that can be used as the base OS and Hypervisor (using KVM or Qemu)
3) include a local mirror of all of the packages needed to accomplish OpenStack deployment with limited or unsable upstream newtork connectivity.

The system assumes:

1) A UCSM managed Cisco UCS compute environment, with an adminstrative user and password available

2) A network configuration north of the UCS system that has 5 networks available:

  Management
  Public Access (API access)
  Public Tenant (for shared tenant VM access)
  Inter-OS service access
  Storage service access

Other networks may also be valid (for example for VLAN based tenant networks).

3) a host or VM in which the ISO can be built, and which may also be used to connect with the UCSM environment to configure it (this may also be a separate machine onto which the newly created ISO is deployed).

Basic Steps
===========

1) Download and install the Ubuntu 12.04.3 LTS x86\_64 server iso, and install this on a machine with a good internet connection

2) Add the git repository management tool:

  sudo apt-get install git -y

3) Become root and grab the install code (this code repository):

  sudo -H bash
  cd /root
  git clone https://github.com/havate/havate-openstack

4) Run the iso installer script:

  cd havate-openstack
  bash ./cd-iso-installer.sh

Note: The installer will create a signing key for havate@havate.project with a password of cloud (that you will need to sign the repository)

5) Take the resulting ISO to your UCSM enviornemnt, and load the ISO onto another maching (can be Virtual or Phsycial, but this second machine needs to be able to access the management IP of the UCSM system).

Support
=======

We're on #havate-openstack on freenode.net, or open an issue here and we'll look to address it.

Support is also available from the folks at 1-Cloud.net



