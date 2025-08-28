#
#
# OpenSAND is an emulation testbed aiming to represent in a cost effective way a
# satellite telecommunication system for research and engineering activities.
#
#
# Copyright © 2020 TAS
#
#
# This file is part of the OpenSAND testbed.
#
#
# OpenSAND is free software : you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see http://www.gnu.org/licenses/.
#
#

# Author: Franklin SIMO <armelfrancklin.simotegueu@viveris.fr>
#         Bastien TAURAN <bastien.tauran@viveris.fr>


GW_ID=0
ST_ID=1
SAT_ID=2
EMU_IFACE=enp0s10
EMU_IP_GW=192.168.18.42
EMU_IP_SAT=192.168.18.1
EMU_IP_ST=192.168.18.15
TAP_IFACE=opensand_tap
TAP_MAC_GW=00:00:00:00:00:01
TAP_MAC_ST=00:00:00:00:00:02
NET_DIGITS=24
ENABLE_COLLECTOR=true
COLLECTOR_IP=10.10.0.142
ENABLE_LOCAL_LOGS=false
LOG_FOLDER=/var/log/opensand

all: clean network run 

clean: stop
	ip link set $(EMU_IFACE) down

network: clean
	ip link set $(EMU_IFACE) up
	sleep 0.1
	ip address flush dev $(EMU_IFACE)
	ip address replace $(EMU_IP_SAT)/$(NET_DIGITS) dev $(EMU_IFACE)

run:
	opensand -i infrastructure_updated.xml -t topology_updated.xml &

stop:
	killall -q opensand || true


.PHONY: all run network clean stop

