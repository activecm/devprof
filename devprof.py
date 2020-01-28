#!/usr/bin/env python3
"""This program imports bro/zeek logs that watch a given network and reports on systems whose volume of traffic (in payload bytes) exceeds a profile assigned to that system."""


import os		#For directory listing and others
import sys
import gzip		#To read gzip compressed files
import re		#For regular expression parsing
import json		#To load user configuration
import math		#For float comparison
try:
	import ipaddress			#IP address/network objects and functions
except ImportError:
	print("Missing ipaddress module; perhaps 'sudo port install py-ipaddress', 'sudo yum install python-ipaddress' or 'sudo -H pip install ipaddress' ?  Exiting.")
	raise


#======== Functions ========
def fail(fail_message):
	"""Print a debug string and exit."""

	sys.stderr.write(str(fail_message) + ', exiting.\n')
	sys.stderr.flush()
	sys.exit(1)


def Debug(DebugStr):
	"""Prints a note to stderr"""
	if Devel != False:
		sys.stderr.write(DebugStr + '\n')
		sys.stderr.flush()


def write_object(filename, generic_object):
	"""Write out an object to a file."""

	try:
		with open(filename, "wb") as write_h:
			write_h.write(generic_object.encode('utf-8'))
	except:
		sys.stderr.write("Problem writing " + filename + ", skipping.")
		raise

	return


def load_json(json_filename, default_content):

	json_to_return = None

	if os.path.exists(json_filename):
		with open(json_filename) as json_h:
			try:
				json_to_return = json.loads(json_h.read())
			except json.decoder.JSONDecodeError:
				sys.stderr.write("Unable to load " + json_filename + " .  Please check that it contains valid json.\n")
				sys.stderr.flush()
				raise
	else:
		json_to_return = default_content
		write_object(json_filename, json.dumps(json_to_return))
		sys.stderr.write("No configuration file " + json_filename + ' .  Using empty configuration.\n')
		sys.stderr.flush()

	return json_to_return


def LoadMacData(MacFile):
	"""Load Ethernet Mac address prefixes from standard locations (from ettercap, nmap, wireshark, and/or arp-scan)."""
	global EtherManuf

	More = ''
	if len(EtherManuf) > 0:
		More = ' more'

	LoadCount = 0

	if os.path.isfile(MacFile):
		try:
			MacHandle = open(MacFile, 'r')

			for line in MacHandle:
				if (len(line) >= 8) and (line[2] == ':') and (line[5] == ':'):
					#uppercase incoming strings just in case one of the files uses lowercase
					MacHeader = line[:8].upper()
					Manuf = line[8:].strip()
					if not MacHeader in EtherManuf:
						EtherManuf[MacHeader] = Manuf
						LoadCount += 1
				elif (len(line) >= 7) and (re.search('^[0-9A-F]{6}[ \t]', line) is not None):
					MacHeader = str.upper(line[0:2] + ':' + line[2:4] + ':' + line[4:6])
					Manuf = line[7:].strip()
					if MacHeader not in EtherManuf:
						EtherManuf[MacHeader] = Manuf
						LoadCount += 1

			MacHandle.close()
			if '00:00:00' in EtherManuf:
				del EtherManuf['00:00:00']		#Not really Xerox
				LoadCount -= 1
			Debug(str(LoadCount) + More + " mac prefixes loaded from " + str(MacFile))
			return True
		except:
			Debug("Unable to load " + str(MacFile))
			return False
	else:
		Debug("Unable to load " + str(MacFile))
		return False


def tree_file_listing(top_level_dir):
	"""Returns a set of files in a directory tree (recursively)."""

	ret_file_list = set()

	if os.path.isdir(top_level_dir):
		for top_level, dirs, files in os.walk(top_level_dir):
			for one_dir in dirs:
				for new_file in tree_file_listing(os.path.join(top_level, one_dir)):
					ret_file_list.add(new_file)
			for one_file in files:
				ret_file_list.add(os.path.join(top_level, one_file))

	return ret_file_list



def load_file_into_originator_stats(incoming_log):
	"""Loads in a single file of Bro/Zeek logs into originator_stats and ips_of_mac."""

	global originator_stats
	global ips_of_mac
	global files_successfully_loaded

	#We unconditionally load these for each new file, as the format may change between files.
	field_pos = {}						#Key: name of field.  Value: position where that field can be found.  Recommend using field_pos.get('fieldname', None)
	field_name = {}						#Key: position in the line.  Value: name of the field.

	load_completed = True

	with gzip.open(incoming_log, 'rt') as bro_h:
		for raw_line in bro_h:
			line = raw_line.strip()
			if line.startswith('#fields'):
				all_names = line.split('\t')[1:]		#[1:] drops the "#fields" label at the far left.
				for x in list(range(0, len(all_names))):	#Load in the file's header so we know which column holds which field.
					field_pos[all_names[x]] = x
					field_name[x] = all_names[x]
				#Sample field_name loaded:
				#{0: 'ts', 1: 'uid', 2: 'id.orig_h', 3: 'id.orig_p', 4: 'id.resp_h', 5: 'id.resp_p', 6: 'proto', 7: 'service', 8: 'duration', 9: 'orig_bytes', 10: 'resp_bytes', 11: 'conn_state', 12: 'local_orig', 13: 'local_resp', 14: 'missed_bytes', 15: 'history', 16: 'orig_pkts', 17: 'orig_ip_bytes', 18: 'resp_pkts', 19: 'resp_ip_bytes', 20: 'tunnel_parents'}
				#Sample field_pos loaded
				#{'duration': 8, 'id.resp_h': 4, 'orig_bytes': 9, 'orig_pkts': 16, 'local_orig': 12, 'tunnel_parents': 20, 'history': 15, 'service': 7, 'proto': 6, 'id.orig_p': 3, 'resp_ip_bytes': 19, 'missed_bytes': 14, 'resp_bytes': 10, 'conn_state': 11, 'id.resp_p': 5, 'orig_ip_bytes': 17, 'id.orig_h': 2, 'ts': 0, 'local_resp': 13, 'uid': 1, 'resp_pkts': 18}
				if 'id.orig_h' not in field_pos or 'id.orig_p' not in field_pos or 'id.resp_p' not in field_pos or 'proto' not in field_pos or 'service' not in field_pos or 'orig_bytes' not in field_pos or 'resp_bytes' not in field_pos:	#We require at least these fields, exit entirely if not present
					Debug(str(incoming_log) + " is missing crucial field.")
					load_completed = False
					break
			elif not line.startswith('#'):
				#FIXME - manually set field positions if not set by now
				fields = line.split('\t')

				src_ip = fields[field_pos['id.orig_h']]

				if fields[field_pos['proto']] == "icmp":		#With icmp, the "type" is stored in id.orig_p.
					conn_key = fields[field_pos['id.orig_p']] + ':' + fields[field_pos['proto']] + ':' + fields[field_pos['service']]
				else:
					conn_key = fields[field_pos['id.resp_p']] + ':' + fields[field_pos['proto']] + ':' + fields[field_pos['service']]
				#At this point we're left with a conn_key like         "1484:tcp:ftp-data"
				#If the profile for this IP lists this specific string, great.  If not, let's strip off the port and see if
				#":tcp:ftp-data" is in the profile for this IP, and use that if so.
				stripped_conn_key = ':' + fields[field_pos['proto']] + ':' + fields[field_pos['service']]
				profile_for_src_ip = ports_for_identifier(src_ip)
				if conn_key not in profile_for_src_ip and stripped_conn_key in profile_for_src_ip:
					#OK, we do have the shortened key, so we use that from here on:
					conn_key = stripped_conn_key

				if src_ip not in originator_stats:
					originator_stats[src_ip] = {}
				if conn_key not in originator_stats[src_ip]:
					originator_stats[src_ip][conn_key] = 0
				if fields[field_pos['orig_bytes']] != '-':
					originator_stats[src_ip][conn_key] += int(fields[field_pos['orig_bytes']])
				if fields[field_pos['resp_bytes']] != '-':
					originator_stats[src_ip][conn_key] += int(fields[field_pos['resp_bytes']])

				if 'orig_l2_addr' in field_pos:
					src_mac = fields[field_pos['orig_l2_addr']].upper()	#This is the mac address from which the packet came, which might be the mac address of the source IP or the mac address of a router in between.
					if not src_mac.startswith('33:33'):			#ipv6 multicast
						if src_mac not in ips_of_mac:
							ips_of_mac[src_mac] = set()
						ips_of_mac[src_mac].add(str(fields[field_pos['id.orig_h']]))

				if 'resp_l2_addr' in field_pos and 'id.resp_h' in field_pos:
					dst_mac = fields[field_pos['resp_l2_addr']].upper()	#This is the mac address to which the packet is going, which might be the mac address of the dest IP or the mac address of a router in between.
					if not dst_mac.startswith('33:33'):
						if dst_mac not in ips_of_mac:
							ips_of_mac[dst_mac] = set()
						ips_of_mac[dst_mac].add(str(fields[field_pos['id.resp_h']]))

	if load_completed:
		files_successfully_loaded = files_successfully_loaded + 1


def merge_two_ranges(first_range, second_range):
	"""When a port is specified twice in two different profiles (such as "22:tcp:ssh": [None, 1000000]" and "22:tcp:ssh": [1000, 100000000]"), we need to pick the more restrictive values in both ranges."""
	#For reference, first_range, second_range, and the returned "[lower_limit, upper_limit]" are both 2 element lists whose values are a number or None (which is "null" in a json file)

	if first_range[0] is None:
		lower_limit = second_range[0]
	elif second_range[0] is None:
		lower_limit = first_range[0]
	else:
		lower_limit = max(first_range[0], second_range[0])

	if first_range[1] is None:
		upper_limit = second_range[1]
	elif second_range[1] is None:
		upper_limit = first_range[1]
	else:
		upper_limit = min(first_range[1], second_range[1])

	#Debug("Merged " + str(first_range) + " and " + str(second_range) + " into [" + str(lower_limit) + ", " + str(upper_limit) + "]")
	return [lower_limit, upper_limit]


def normalize_bytes(byte_limit):
	"""Turn nnnMB into nnn*1048576, etc.  Works for KB, MB, GB, TB, PB."""
	#We use KB/MB... as 1000^N, and KiB/MiB... as 1024^N .  See https://en.wikipedia.org/wiki/Binary_prefix

	retval = None

	if byte_limit is None:
		retval = None
	elif isinstance(byte_limit, str):
		if byte_limit.endswith("KB"):
			retval = int(byte_limit[:-2]) * 1000
		elif byte_limit.endswith("MB"):
			retval = int(byte_limit[:-2]) * 1000000
		elif byte_limit.endswith("GB"):
			retval = int(byte_limit[:-2]) * 1000000000
		elif byte_limit.endswith("TB"):
			retval = int(byte_limit[:-2]) * 1000000000000
		elif byte_limit.endswith("PB"):
			retval = int(byte_limit[:-2]) * 1000000000000000
		elif byte_limit.endswith("KiB"):
			retval = int(byte_limit[:-3]) * 1024
		elif byte_limit.endswith("MiB"):
			retval = int(byte_limit[:-3]) * 1048576
		elif byte_limit.endswith("GiB"):
			retval = int(byte_limit[:-3]) * 1073741824
		elif byte_limit.endswith("TiB"):
			retval = int(byte_limit[:-3]) * 1099511627776
		elif byte_limit.endswith("PiB"):
			retval = int(byte_limit[:-3]) * 1125899906842624
		else:
			retval = int(byte_limit)
	elif isinstance(byte_limit, (int, float)):
		retval = byte_limit
	else:
		fail("Unrecognized value: " + str(byte_limit))

	return retval


def create_ports_for_ip(user_profiles_for_ip, user_ports_for_profile):
	"""Generate and return ports_for_ip based on profiles_for_ip and user_ports_for_profile."""

	created_ports_for_ip = {}
	created_networks_for_ip = {}

	if 'system_profile_pairs' not in user_profiles_for_ip:
		fail("Profiles_for_ip does not start with system_profile_pairs")

	for one_pair in user_profiles_for_ip['system_profile_pairs']:
		#one_pair looks like:	{
		#				"systems": ["10.0.0.41", "10.10.10.10"],
		#				"profiles": ["mac", "traceroute", "general_traffic", "local_lan"]
		#			},

		system_list = one_pair["systems"]
		if not isinstance(system_list, list):		#isinstance(system_list, (str, unicode)) not needed
			fail("One of the profiles_for_ip ip lists is not a list")
		profile_list = one_pair["profiles"]
		for one_profile in profile_list:
			if one_profile not in user_ports_for_profile:
				fail("No profile named " + str(one_profile) + " in ports_for_profile")

		for one_ip in system_list:
			if '/' in one_ip:
				#This is a subnet, so we make an ipaddress object for it
				one_ip = ipaddress.ip_network(one_ip, strict=False)

				if one_ip not in created_networks_for_ip:
					created_networks_for_ip[one_ip] = {}
				for one_profile in profile_list:
					for one_port in user_ports_for_profile[one_profile].keys():
						normalized_min = normalize_bytes(user_ports_for_profile[one_profile][one_port][0])
						normalized_max = normalize_bytes(user_ports_for_profile[one_profile][one_port][1])
						created_networks_for_ip[one_ip][one_port] = merge_two_ranges([normalized_min, normalized_max], created_networks_for_ip[one_ip].get(one_port, [None, None]))	#If we already had min/max for this port, find the most restrictive intersection with old and new min/max, otherwise just use the new min/max
			else:
				#This is an IP address, mac address, or hostname
				if one_ip not in created_ports_for_ip:
					created_ports_for_ip[one_ip] = {}
				for one_profile in profile_list:
					for one_port in user_ports_for_profile[one_profile].keys():
						normalized_min = normalize_bytes(user_ports_for_profile[one_profile][one_port][0])
						normalized_max = normalize_bytes(user_ports_for_profile[one_profile][one_port][1])
						created_ports_for_ip[one_ip][one_port] = merge_two_ranges([normalized_min, normalized_max], created_ports_for_ip[one_ip].get(one_port, [None, None]))		#If we already had min/max for this port, find the most restrictive intersection with old and new min/max, otherwise just use the new min/max

	return created_ports_for_ip, created_networks_for_ip



def ports_for_identifier(one_id):
	"""Returns the list of port specifications for a given identifier (ipv4 address, ipv6 address, (or, future enhancement, mac address))."""

	#Remembers what profile we've found for a given IP address so we only have to look it up once.
	if "pfi_cache" not in ports_for_identifier.__dict__:
		ports_for_identifier.pfi_cache = {}

	if "ports_for_ip" not in ports_for_identifier.__dict__:
		ports_for_identifier.ports_for_ip = {}		#Dict: Key: IP, value: dictionary with portspec as key, 2 element list ([min, max]) as value
		ports_for_identifier.networks_for_ip = {}	#Dict: Key: ipaddress network object, value: dictionary with portspec as key, 2 element list ([min, max]) as value
		ports_for_identifier.ports_for_ip, ports_for_identifier.networks_for_ip = create_ports_for_ip(profiles_for_ip, ports_for_profile)	#This is populated from profiles_for_ip and named_profiles.  Key: IP, value: dictionary with portspec as key, 2 element list ([min, max]) as value

	ip_profile = {}

	if one_id in ports_for_identifier.pfi_cache:					#If in cache already, use that.
		ip_profile = ports_for_identifier.pfi_cache[one_id]
	elif one_id in ports_for_identifier.ports_for_ip:							#If the id exactly matches an IP address, use that.
		ip_profile = ports_for_identifier.ports_for_ip[one_id]
		ports_for_identifier.pfi_cache[one_id] = ip_profile
	else:
		old_prefix_len = None
		ip_obj = ipaddress.ip_address(one_id)					#Make an ip address object to check against supplied networks
		for one_net in ports_for_identifier.networks_for_ip:
			if ip_obj in one_net:						#If we match any of the supplied IP networks, use the list for it.
				if ip_profile:						#If we match more than one...
					if one_net.prefixlen > old_prefix_len:		#And this new one is a smaller subnet (greater /N)...
						ip_profile = ports_for_identifier.networks_for_ip[one_net]	#Use it.
						ports_for_identifier.pfi_cache[one_id] = ip_profile
						old_prefix_len = one_net.prefixlen
				else:
					#We have _not_ already matched a previous network, so just use this one.
					ip_profile = ports_for_identifier.networks_for_ip[one_net]
					ports_for_identifier.pfi_cache[one_id] = ip_profile
					old_prefix_len = one_net.prefixlen

	return ip_profile



def manuf_label(mac_addr, ManufTable):
	"""Returns the correct Manufacturer name for a given mac address."""

	if mac_addr[:8] == '-':
		ret_manuf_label = ""
	elif mac_addr[:14].startswith(('00:00:5E:00:01')):			#https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml#ethernet-numbers-1
		ret_manuf_label = "VRRP Router"
	elif mac_addr[:14].startswith(('00:00:5E:00:02')):
		ret_manuf_label = "IPv6 VRRP Router"
	elif mac_addr[:8].startswith(('01:00:5E', '33:33:', 'FF:FF:FF')):
		ret_manuf_label = "Ethernet broadcast/multicast"
	elif mac_addr[:8] in ManufTable:
		ret_manuf_label = ManufTable[mac_addr[:8]]
	else:
		ret_manuf_label = 'Unrecognized mac prefix'

	return ret_manuf_label


def output_results(output_lists, ips_of_mac_dict, user_args, EtherManufDict):
	"""Print the output tables."""

	if user_args['web'] and user_args['header']:
		print("<html>\n<head>\n<title>device_profile stats</title>\n</head>\n<body>")

	if output_lists:
		if user_args['web']:
			print("<table border=1>")
			print("<tr><th>IP</th><th>Protocol</th><th>Bytes</th></tr>")
		current_header = ''
		for value_list in sorted(output_lists):
			if value_list[0] != current_header:
				if user_args['web']:
					print('<tr><th colspan=4 bgcolor="#00AAAA" align=left>' + str(value_list[0]) + "</th></tr>")
				else:
					print("======== " + value_list[0])
				current_header = value_list[0]
			if user_args['web']:
				print("<tr><td>" + str(value_list[1]) + "</td><td align=right>" + str(value_list[2]) + "</td><td align=right>" + str("{:,}".format(value_list[3])) + "</td></tr>")
			else:
				print('{1:<40s} {2:>20s} {3:>18,}'.format(*value_list))
		if user_args['web']:
			print("</table>")

	if ips_of_mac_dict:
		if user_args['web']:
			print("<hr>\n<table border=1>")
			print('<tr><th colspan=3 bgcolor="#ffffff">Mac addresses</th></tr>')
		else:
			print('')
			print("======== Mac addresses")


		for one_mac in sorted(ips_of_mac_dict.keys()):
			my_manuf = manuf_label(one_mac, EtherManufDict)

			if len(ips_of_mac_dict[one_mac]) < 20:
				ip_list = ', '.join(sorted(ips_of_mac_dict[one_mac]))
			else:
				ip_list = str(len(ips_of_mac_dict[one_mac])) + " ips"

			if user_args['web']:
				print("<tr><td>" + str(one_mac) + "</td><td>" + str(my_manuf) + "</td><td>" + str(ip_list) + "</td></tr>")
			else:
				print('{0:<18s} {1:<35s} {2:<s}'.format(str(one_mac), str(my_manuf), str(ip_list)))


		if user_args['web']:
			print("</table>")

	if user_args['web'] and user_args['header']:
		print("</body>\n</html>")



#======== Global variables ========
devprof_version = '2.2'

EtherManuf = {}			#String dictionary: for a given key of the first three uppercase octets of a mac address ("00:01:0F"), who made this card?
originator_stats = {}		#Dict; key is orig_ip/port/ip_proto/app_proto , value is total payload bytes (orig+responder)
ips_of_mac = {}			#Dict; key is the mac address, value is a list of IPs associated with that mac.  one IP means that's almost certainly the mac of that system, more than one means its the mac of a router leading to more than one system.
files_successfully_loaded = 0

Devel = False
default_config_dir = os.environ["HOME"] + '/.config/devprof/'
pfi_filename = 'profiles_for_ip.json'
pfp_filename = 'ports_for_profile.json'




#======== Code ========
if __name__ == "__main__":

#==== Configuration ====
	import argparse

	parser = argparse.ArgumentParser(description='devprof version ' + str(devprof_version))
	parser.add_argument('-c', '--config', help='Directory that holds configuration files (Default: ' + str(default_config_dir) + ')', default=default_config_dir, required=False)
	parser.add_argument('-t', '--time', help='Time (in hours) covered by logs (default: number of logs loaded).', required=False, type=float)
	parser.add_argument('-d', '--directory', help='Directory that holds Bro/Zeek log files.', required=True)
	parser.add_argument('-w', '--web', help='Show in web (HTML) format (default: text)', required=False, default=False, action='store_true')
	parser.add_argument('--header', help='Add HTML header and footer', required=False, default=False, action='store_true')
	parser.add_argument('--debug', help='Show additional debugging information on stderr', required=False, default=False, action='store_true')
	cl_args = vars(parser.parse_args())

	Devel = cl_args['debug']

	config_dir = cl_args['config']
	if not os.path.isdir(config_dir):
		fail("No configuration directory " + config_dir + " : please create it and rerun this program")

	profiles_for_ip = load_json(config_dir + '/' + pfi_filename, {"system_profile_pairs": [{"systems": ["0.0.0.0/0", "::/0"], "profiles": []}]})
	ports_for_profile = load_json(config_dir + '/' + pfp_filename, {})

#==== Support data ====
	for oneMacFile in ('/usr/share/ettercap/etter.finger.mac', '/opt/local/share/ettercap/etter.finger.mac', '/usr/share/nmap/nmap-mac-prefixes', '/opt/local/share/nmap/nmap-mac-prefixes', '/usr/share/wireshark/manuf', '/opt/local/share/wireshark/manuf', '/usr/share/ethereal/manuf', '/usr/share/arp-scan/ieee-oui.txt', '/opt/local/share/arp-scan/ieee-oui.txt'):
		if os.path.isfile(oneMacFile):
			LoadMacData(oneMacFile)
	if len(EtherManuf) == 0:
		Debug("None of the default mac address listings found.  Please install ettercap, nmap, wireshark, and/or arp-scan.")
	else:
		Debug(str(len(EtherManuf)) + " mac prefixes loaded.")

#==== Load Bro/Zeek logs ====
	bro_log_dir = cl_args['directory']
	if bro_log_dir[-1:] != '/':
		bro_log_dir = bro_log_dir + '/'				#Make sure it ends with a slash.

	for one_log in tree_file_listing(bro_log_dir):
		if one_log.startswith(bro_log_dir + 'conn') and os.path.isfile(one_log):
			Debug(one_log)
			load_file_into_originator_stats(one_log)

	if files_successfully_loaded == 0:
		fail("Unable to successfully load any files")

	if 'hours' in cl_args:						#If we have anything other than 24 hours of logs, this adjusts the total paylod to be payload over 24 hours (which all profiles assume)
		if math.isclose(cl_args['hours'], 0.0, rel_tol=1e-09):
			fail("specified time is too close to 0")
		else:
			multiplier = float(24) / cl_args['hours']	#Use user-supplied value if there is one,
	else:
		multiplier = float(24) / files_successfully_loaded	#...otherwise go by the number of logs successfully loaded.

#==== Compare loaded traffic stats to the user-defined limits ====
	out_lists = []

	for one_src_ip in originator_stats.keys():
		my_ip_profile = ports_for_identifier(one_src_ip)

		for one_proto in originator_stats[one_src_ip]:
			this_proto_category = 'unknown'
			for one_prof in my_ip_profile.keys():
				if one_proto == one_prof:
					if this_proto_category not in ('too_little', 'too_much'):
						this_proto_category = 'in_range'

					if my_ip_profile[one_prof][0] is not None and (originator_stats[one_src_ip][one_proto] * multiplier) < my_ip_profile[one_prof][0]:		#Traffic for this port is lower than profile minimum for this port (if there is one)
						this_proto_category = 'too_little'
					elif my_ip_profile[one_prof][1] is not None and (originator_stats[one_src_ip][one_proto] * multiplier) >= my_ip_profile[one_prof][1]:		#Traffic for this port is greater than or equal to profile maximum for this port (if there is one)
						this_proto_category = 'too_much'
			if this_proto_category != 'in_range':
				out_lists.append([this_proto_category, one_src_ip, one_proto, originator_stats[one_src_ip][one_proto]])
			#else:
			#	print(this_proto_category)



#==== Display results ====
	output_results(out_lists, ips_of_mac, cl_args, EtherManuf)
