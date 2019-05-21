#!/usr/bin/python3


#=============
# homenetGrapher.py
# solely for depicting internal-to-internal network traffic, ideally running on a cron schedule and regularly monitored
# for SMALL to MEDIUM-sized networks
#
# v0.1 - 20 May 2019
# 	- first version, implements a configuration file requirement, basic labels on nodes, command line args, exclusions in the config
#
# use Zeek (Bro)'s conn.log and homenets.cfg to create visual images with GraphViz depicting traffic solely between internal hosts
#
# homenets.cfg
# add CIDRs representing your network ranges to homenets.cfg
# add individual IPs to ignore
#
# TODO
# - write to JSON and send to a web server running d3 and d3-force
# - display changes over time / over last x runs
# - Zeek uid pairing and/or additional triggering based off notices.log events
# - address coverage gaps between log rotation (look at a log that changed since last being read, which has also rotated and been gzip'd)#
# - better config parsing
#=============


import getopt, ipaddress, os, sys, time


now = time.strftime('%Y-%m-%d_%H:%M:%S')


def helpy():
	print()
	print('Usage:')
	print('\thomenet-graph.py --log [log-path] --config [config-path] [--dot | --circo | --neato] [--help]')
	print()
	print('\t-l / --log\t\tpath of the Zeek (Bro) conn.log to be visualized')
	print('\t-g / --config\t\tpath of the homenets.cfg (line-separated file containing your network\'s CIDR ranges, one-per-line')
	print('\t-o / --output\t\toutput location (NOT filename) for the final image')
	print('\t-d / --dot\t\toutputs image in dot format')
	print('\t-c / --circo\t\toutputs image in circo format')
	print('\t-n / --neato\t\toutputs image in neato format')
	print()
	print('Examples:')
	print('\thomenetGrapher.py --config /etc/opt/homenetGrapher/homenets.cfg --log /path-to-bro/conn.log --output /var/log --dot --circo --neato')
	print('\thomenetGrapher.py -g /etc/opt/homenetGrapher/homenets.cfg -l /path-to-bro/conn.log -o /var/log --dot --circo --neato')
	print()


try:
	opts, args = getopt.getopt(sys.argv[1:], "hcdng:l:o:", ["help", "circo", "dot", "neato", "config=", "log=", "output="])
except Exception as e:
	print(str(e))
	helpy()
	sys.exit(2)


makeimg = False
circ = False
dott = False
neat = False
try:
	for opt, arg in opts:
		if opt in ["-h", "--help"]:
			helpy()
			sys.exit(1)
		if opt in ["-g", "--config"]:
			configLocation = arg
		if opt in ["-o", "--output"]:
			outputPath = str(arg).rstrip('/')
			dotFile = str(outputPath+'/homenet-graph-{}-DOTFILE.dot'.format(now))
		if opt in ["-c", "--circo"]:
			circoImage = str(outputPath+'/homenet-graph-{}-circo.png'.format(now))
			circ = True
			makeimg = True
		if opt in ["-d", "--dot"]:
			dotImage = str(outputPath+'/homenet-graph-{}-dot.png'.format(now))
			dott = True
			makeimg = True
		if opt in ["-n", "--neato"]:
			neatoImage = str(outputPath+'/homenet-graph-{}-neato.png'.format(now))
			neat = True
			makeimg = True
		if opt in ["-l", "--log"]:
			logLocation = str(arg).rstrip('/')
except Exception as e:
	print(str(e))
	helpy()
	sys.exit(1)


with open(configLocation, mode='r', encoding="utf-8") as configfile:
	homenets = []
	exclude = []
	for line in configfile:
		if not line.startswith('#'):
			if len(line) >= 7:
				if not line.startswith('EXCLUDE'):
					homenets.append(line.rstrip('\n'))
				else:
					exclude.append(line.split()[1].rstrip('\n'))
	configfile.close()


def checkIps(s, d):
	for cidr in homenets:
		if s not in exclude and d not in exclude:
			if ipaddress.ip_address(s) in ipaddress.ip_network(cidr):
				for cidr in homenets:
					if ipaddress.ip_address(d) in ipaddress.ip_network(cidr):
						return True


connections = []
with open(logLocation, mode="r", encoding="utf-8") as logfile:
	c = 0
	for line in logfile:
		if not line.startswith('#'):
			l = line.split('\t')
			ts = l[0]
			sip = l[2]
			dip = l[4]
			spt = l[3] # if icmp, this is type
			dpt = l[5] # if icmp, this is code
			pro = l[6]
			srv = l[7]
			sta = l[11]
#			his = l[15]
			if checkIps(sip, dip):
				color = 'black'
				if pro == 'tcp':
					color = 'blue'
					if srv == 'ssl':
						color = 'cyan'
					if srv in ['ftp', 'ftp-data', 'ssh', 'scp', 'telnet', 'ms-wbt-server', 'tftp', 'ni-ftp', 'sftp', 'bftp', 'subntbcst_tftp', 'mftp', 'ftp-agent', 'pftp', 'ftps-data', 'ftps', 'tftp-mcast', 'etftp', 'utsftp', 'aaftp', 'gsiftp', 'odette-ftp', 'odette-ftps', 'tftps', 'kftp', 'kftp-data', 'mcftp', 'netconf-ssh', 'sdo-ssh', 'ssh-mgmt', 'rtelnet', 'telnets', 'skytelnet', 'hp-3000-telnet', 'tl1-telnet', 'telnetcpcd', 'scpi-telnet', 'ktelnet', 'rcp']:
						color = 'red'
				elif pro == 'udp':
					color = 'orange'
				elif pro == 'icmp':
					color = 'purple'
					dpt = '{}:{}'.format(spt, dpt)
				connections.append('"{}" -> "{}" [label="dpt:{}/{}/{} {}", color="{}"]'.format(sip, dip, dpt, pro, srv, sta, color))
	logfile.close()


if makeimg:
	print('Making {}'.format(dotFile))
	with open(dotFile, 'w') as o:
		o.write('digraph output {\nnode[shape = Mrecord];\nfontsize=16;\nnodesep=1.5;\nranksep=1;\nrankdir=LR;\n')
		connections = list(set(connections))
		for c in connections:
			o.write(c+';\n')
		o.write('\n}')
	o.close()
	print('Making output images...  these may take a minute to render.')
	try:
		if dott:
			print('Making {}'.format(dotImage))
			os.popen('dot -Tpng {} -o {}'.format(dotFile, dotImage))
		if circ:
			print('Making {}'.format(circoImage))
			os.popen('circo -Tpng {} -o {}'.format(dotFile, circoImage))
		if neat:
			print('Making {}'.format(neatoImage))
			os.popen('neato -Goverlap=scale -Tpng {} -o {}'.format(dotFile, neatoImage))
	except Exception as e:
		print(str(e))
		print('ERROR:  "dot", "circo", and/or "neato" not found via path variable - is GraphViz installed on this system?')
		sys.exit(5)
	# comment the remove line to preserve the dot-formatted text file used to generate the images via GraphViz
	# time.sleep(0.5) # this gives dot/circo/neato time to ingest the config before removing it
	# os.remove(dotFile)
else:
	print()
	print('You didn\'t specify a format for the output graph.')
	helpy()
	sys.exit(1)
