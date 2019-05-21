# homenetGrapher
Force-Directed Graph Generator for Internal-to-Internal Network Traffic Analysis on **SMALL** to **MEDIUM** Networks

## Purpose
- Visualize internal-to-internal network traffic to identify hosts performing potentially unauthorized communications

## Features
- Config for specifying both a) network address space in use, and b) individual IPs to ignore
- Dot (preferred), Circo, and Neato flags, for specifying one or more outputs
- Color-coding and labels for presenting summary information for each link

## Usage
```
# use a cronjob to run this script as needed for analysis

homenetGrapher.py --log [log-path] --config [config-path] [--dot | --circo | --neato] [--help]

	-l / --log		path of the Zeek (Bro) conn.log to be visualized
	-g / --config		path of the homenets.cfg (line-separated file containing your network's CIDR ranges, one-per-line
	-o / --output		output location (NOT filename) for the final image
	-d / --dot		outputs image in dot format
	-c / --circo		outputs image in circo format
	-n / --neato		outputs image in neato format

Examples:
	homenetGrapher.py --config /etc/opt/homenetGrapher/homenets.cfg --log /path-to-bro/conn.log --output /var/log --dot --circo --neato
	homenetGrapher.py -g /etc/opt/homenetGrapher/homenets.cfg -l /path-to-bro/conn.log -o /var/log --dot --circo --neato
```

## TODO
- write to JSON and send to a web server running d3 and d3-force
- display changes over time / over last x runs
- Zeek uid pairing and/or additional triggering based off notices.log events
- address coverage gaps between log rotation (look at a log that changed since last being read, which has also rotated and been gzip'd)
- better config parsing
