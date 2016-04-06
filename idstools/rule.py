# Copyright (c) 2011 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

""" Module for parsing Snort-like rules.

Parsing is done using regular expressions and the job of this module
is to do its best at parsing out fields of interest from the rule
rather than perform a sanity check.

The methods that parse multiple rules for a provided input
(parse_file, parse_fileobj) return a list of rules instead of dict
keyed by ID as its not the job of this module to detect or deal with
duplicate signature IDs.
"""

from __future__ import print_function
import json
import re
import logging

logger = logging.getLogger(__name__)

# Rule actions we expect to see.
actions = (
    "alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")

# Compiled regular expression to detect a rule and break out some of
# its parts.
rule_pattern = re.compile(
    r"^(?P<enabled>#)*\s*"      # Enabled/disabled
    r"(?P<raw>"
    r"(?P<action>%s)\s*"        # Action
    r"[^\s]*\s*"                # Protocol
    r"[^\s]*\s*"                # Source address(es)
    r"[^\s]*\s*"                # Source port
    r"(?P<direction>[-><]+)\s*"	# Direction
    r"[^\s]*\s*"		        # Destination address(es)
    r"[^\s]*\s*"                # Destination port
    r"\((?P<options>.*)\)\s*" 	# Options
    r")"
    % "|".join(actions))

# Another compiled pattern to detect preprocessor rules.  We could
# construct the general rule re to pick this up, but its much faster
# this way.
decoder_rule_pattern = re.compile(
    r"^(?P<enabled>#)*\s*"	# Enabled/disabled
    r"(?P<raw>"
    r"(?P<action>%s)\s*"	# Action
    r"\((?P<options>.*)\)\s*" 	# Options
    r")"
    % "|".join(actions))

# Regular expressions to pick out options.
option_patterns = (
    re.compile("(msg)\s*:\s*\"(.*?)\";"),
    re.compile("(gid)\s*:\s*(\d+);"),
    re.compile("(sid)\s*:\s*(\d+);"),
    re.compile("(rev)\s*:\s*(\d+);"),
    re.compile("(metadata)\s*:\s*(.*?);"),
    re.compile("(flowbits)\s*:\s*(.*?);"),
    re.compile("(flow)\s*:\s*(.*?);"),
    re.compile("(reference)\s*:\s*(.*?);"),
    re.compile("(classtype)\s*:\s*(.*?);"),
    re.compile("(priority)\s*:\s*(.*?);"),
    re.compile("(content)\s*:\s*(.*?);"),
    re.compile("(nocase)\s*:\s*(.*?);"),
    re.compile("(rawbytes)\s*:\s*(.*?);"),
    re.compile("(offset)\s*:\s*(.*?);"),
    re.compile("(depth)\s*:\s*(.*?);"),
    re.compile("(distance)\s*:\s*(.*?);"),
    re.compile("(within)\s*:\s*(.*?);"),
    re.compile("(dnp3_cmd_fc)\s*:\s*(\d+);"),
    re.compile("(threshold)\s*:\s*(.*?);"),
    re.compile("(pcre)\s*:\s*(.*?);"),
    re.compile("(dsize)\s*:\s*(.*?);"),
    re.compile("(byte_jump)\s*:\s*(.*?);"),
    re.compile("(byte_test)\s*:\s*(.*?);"),
    re.compile("(isdataat)\s*:\s*(.*?);"),
    re.compile("(flags)\s*:\s*(.*?);"),
    re.compile("(dnp3_checksum)\s*:\s*(.*?);"),
    re.compile("(dnp3_cmd_ot)\s*:\s*(.*?);"),
    # re.compile("(http_client_body)\s*:\s*(.*?);"),
    # re.compile("(http_cookie)\s*:\s*(.*?);"),
    # re.compile("(http_raw_cookie)\s*:\s*(.*?);"),
    # re.compile("(http_header)\s*:\s*(.*?);"),
    # re.compile("(http_raw_header)\s*:\s*(.*?);"),
    # re.compile("(http_method)\s*:\s*(.*?);"),
    # re.compile("(http_uri)\s*:\s*(.*?);"),
    # re.compile("(http_raw_uri)\s*:\s*(.*?);"),
    # re.compile("(http_stat_code)\s*:\s*(.*?);"),
    # re.compile("(http_stat_msg)\s*:\s*(.*?);"),
    # re.compile("(fast_pattern)\s*:\s*(.*?);"),
)

class Rule(dict):
    """ Class representing a rule.

    The Rule class is a class that also acts like a dictionary.

    Dictionary fields:

    - **group**: The group the rule belongs to, typically the filename.

    - **enabled**: True if rule is enabled (uncommented), False is
        disabled (commented)

    - **action**: The action of the rule (alert, pass, etc) as a
        string

    - **direction**: The direction string of the rule.

    - **gid**: The gid of the rule as an integer

    - **sid**: The sid of the rule as an integer

    - **rev**: The revision of the rule as an integer

    - **msg**: The rule message as a string

    - **flowbits**: List of flowbit options in the rule

    - **metadata**: Metadata values as a list

    - **reference**: Reference as a string

    - **classtype**: The classification type

    - **priority**: The rule priority, 0 if not provided
content
    - **raw**: The raw rule as read from the file or buffer

    :param enabled: Optional parameter to set the enabled state of the rule
    :param action: Optional parameter to set the action of the rule
    """

    def __init__(self, enabled=None, action=None, group=None ):
        dict.__init__(self)
        self["enabled"] = enabled
        self["action"] = action
        self["direction"] = None
        self["group"] = group
        self["sid"] = None
        self["rev"] = None
        self["msg"] = None,
        self["reference"] = None
        self["classtype"] = None
        self["priority"] = 0
        self["raw"] = None
        self["content"] = []
        self["nocase"] = []
        self["rawbytes"] = []
        self["offset"] = []
        self["depth"] = []
        self["distance"] = []
        self["within"] = []
        self["source-ip"] = None
        self["source-port"] = None
        self["destination-ip"] = None
        self["destination-port"] = None
        self["transport"] = None
        # self["http_client_body"] = []
        # self["http_cookie"] = []
        # self["http_raw_cookie"] = []
        # self["http_header"] = []
        # self["http_raw_header"] = []
        # self["http_method"] = []
        # self["http_uri"] = []
        # self["http_raw_uri"] = []
        # self["http_stat_code"] = []
        # self["http_stat_msg"] = []
        # self["fast_pattern"] = []


    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the rule.

        :returns: A tuple (gid, sid) representing the ID of the rule
        :rtype: A tuple of 2 ints
        """
        return (int(self.gid), int(self.sid))

    @property
    def idstr(self):
        return "[%s:%s]" % (str(self.gid), str(self.sid))

    def brief(self):
        """ A brief description of the rule.

        :returns: A brief description of the rule
        :rtype: string
        """
        return "%s[%d:%d] %s" % (
            "" if self.enabled else "# ", self.gid, self.sid, self.msg)

    def __hash__(self):
        return self["raw"].__hash__()

    def __str__(self):
        """ The string representation of the rule.

        If the rule is disabled it will be returned as commented out.
        """
        return "%s%s" % ("" if self.enabled else "# ", self.raw)

def isRule(buf):
    m = rule_pattern.match(buf) or decoder_rule_pattern.match(buf)
    if not m:
        return False
    return True

def parse(buf, group=None):
    """ Parse a single rule for a string buffer.

    :param buf: A string buffer containing a single Snort-like rule

    :returns: An instance of of :py:class:`.Rule` representing the parsed rule
    """
    m = rule_pattern.match(buf) or decoder_rule_pattern.match(buf)
    if not m:
        return

    rule = Rule(enabled=True if m.group("enabled") is None else False,
                action=m.group("action"),
                group=group)

    rule["direction"] = m.groupdict().get("direction", None)

    options = m.group("options")


    for p in option_patterns:

        for opt, val in p.findall(options):
        #First if is for value that are saved at the json as INT's (without parenthesis)
            if opt in ["gid", "sid", "rev", "priority", "dnp3_cmd_fc", "dnp3_cmd_ot"]:
                rule[opt] = int(val)
            elif opt in ["metadata", "flow", "flowbits"]:
                rule[opt] = [v.strip() for v in val.split(",")]
            elif opt == "content":
                rule.content.append('\"data\" : ' + val)
            elif opt == "nocase":
                rule.nocase.append(','+'nocas : ' + val)
            elif opt == "rawbytes":
                rule.rawbytes.append(','+'rawbytes : ' + val)
            elif opt == "offset":
                rule.offset.append(','+'\"offset\" : ' + val)
            elif opt == "depth":
                rule.depth.append(','+'\"depth\" : ' + val)
            elif opt == "distance":
                rule.distance.append(','+'distance : ' + val)
            elif opt == "within":
                rule.within.append(','+'within : ' + val)
            elif opt == "pcre":
                rule[opt] = val.replace('"', '')
            elif opt == "dsize":
                rule[opt] = int(val.replace('>', '').strip())
            elif opt == "byte_test":
                bytetestdict = {}
                vallist = []
                vallist = val.split(',')
                for i in xrange(len(vallist)):
                    vallist[i] = vallist[i].strip()
                bytetestdict['bytes-to-convert'] =int(vallist[0])
                bytetestdict['operator'] = vallist[1]
                bytetestdict['value'] = vallist[2]
                bytetestdict['offset'] =  int(vallist[3])
                rule[opt.replace('_','-')] = bytetestdict
            elif opt == "isdataat":
                isdataatdict = {}
                vallist = []
                vallist = val.split(',')
                for i in xrange(len(vallist)):
                    vallist[i] = vallist[i].strip()
                isdataatdict['value'] = int(vallist[0])
                if 'relative' in vallist:
                    isdataatdict['relative'] = True
                else:
                    isdataatdict['relative'] = False
                if 'negative' in vallist:
                    isdataatdict['negative'] = True
                else:
                    isdataatdict['negative'] = False
                rule[opt] = isdataatdict
            elif opt == "byte_jump":
                bytejumpdict = {}
                vallist = []
                vallist = val.split(',')
                for i in xrange(len(vallist)):
                    vallist[i] = vallist[i].strip()
                bytejumpdict['bytes-to-convert'] = int(vallist[0])
                bytejumpdict['offset'] = int(vallist[1])
                if 'align' in vallist:
                    bytejumpdict['align'] = True
                else:
                    bytejumpdict['align'] = False
                if 'big' in vallist:
                    bytejumpdict['big-endian'] = True
                else:
                    if 'little' in vallist:
                        bytejumpdict['big-endian'] = False
                    else:
                        bytejumpdict['big-endian'] = True
                if 'dce' in vallist:
                    bytejumpdict['dce'] = True
                else:
                    bytejumpdict['dce'] = False
                if 'from_beginning' in vallist:
                    bytejumpdict['from_beginning'] = True
                else:
                    bytejumpdict['from_beginning'] = False
                if 'relative' in vallist:
                    bytejumpdict['relative'] = True
                else:
                    bytejumpdict['relative'] = False
                rule[opt.replace('_','')] = bytejumpdict
            else:
                rule[opt] = val


    rule["raw"] = m.group("raw").strip()

    for x in xrange(len(rule['content'])):

        if len(rule['nocase']) >= x+1 and len(rule['nocase'][x]) !=0 :
            rule['content'][x] = rule['content'][x] +' '+ rule['nocase'][x]

        if len(rule['rawbytes']) >= x+1 and len(rule['rawbytes'][x]) !=0:
            rule['content'][x] = rule['content'][x] +' '+ rule['rawbytes'][x]

        if len(rule['offset']) >= x+1 and len(rule['offset'][x]) !=0:
            rule['content'][x] = rule['content'][x] +' '+ rule['offset'][x]

        if len(rule['depth']) >= x+1 and len(rule['depth'][x]) !=0:
            rule['content'][x] = rule['content'][x] +' '+ rule['depth'][x]

        if len(rule['distance']) >= x+1 and len(rule['distance'][x]) !=0:
            rule['content'][x] = rule['content'][x] +' '+ rule['distance'][x]

        if len(rule['within']) >= x+1 and len(rule['within'][x]) !=0:
            rule['content'][x] = rule['content'][x] +' '+ rule['within'][x]

    del rule['nocase']
    del rule['rawbytes']
    del rule['offset']
    del rule['depth']
    del rule['distance']
    del rule['within']

    params  = removeAfter(buf, "(")

    param_list = params.split()

    rule['transport'] = param_list[1]
    rule["source-ip"] = param_list[2] 
    rule["source-port"] =param_list[3]
    rule["destination-ip"] =param_list[5] 
    rule["destination-port"] =param_list[6]

    return rule

def removeAfter(string, suffix):
    return string[:string.index(suffix)]

def parse_fileobj(fileobj, group=None):
    """ Parse multiple rules from a file like object.

    Note: At this time rules must exist on one line.

    :param fileobj: A file like object to parse rules from.

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    rules = []
    for line in fileobj:
        try:
            if type(line) == type(b""):
                line = line.decode()
        except:
            pass
        try:
            rule = parse(line, group)
            if rule:
                rules.append(rule)
        except:
            logger.error("failed to parse rule: %s" % (line))
            raise
    return rules

def parse_file(filename, group=None):
    """ Parse multiple rules from the provided filename.

    :param filename: Name of file to parse rules from

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    with open(filename) as fileobj:
        return parse_fileobj(fileobj, group)

class FlowbitResolver(object):

    setters = ["set", "setx", "unset", "toggle"]
    getters = ["isset", "isnotset"]

    def __init__(self):
        self.enabled = []

    def resolve(self, rules):
        required = self.get_required_flowbits(rules)
        enabled = self.set_required_flowbits(rules, required)
        if enabled:
            self.enabled += enabled
            return self.resolve(rules)
        return self.enabled

    def set_required_flowbits(self, rules, required):
        enabled = []
        for rule in [rule for rule in rules.values() if not rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in required:
                    rule.enabled = True
                    enabled.append(rule)
        return enabled

    def get_required_rules(self, rulemap, flowbits, include_enabled=False):
        """Returns a list of rules that need to be enabled in order to satisfy
        the list of required flowbits.

        """
        required = []

        for rule in [rule for rule in rulemap.values()]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in flowbits:
                    if rule.enabled and not include_enabled:
                        continue
                    required.append(rule)

        return required

    def get_required_flowbits(self, rules):
        required_flowbits = set()
        for rule in [rule for rule in rules.values() if rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.getters:
                    required_flowbits.add(value)
        return required_flowbits

    def parse_flowbit(self, flowbit):
        tokens = flowbit.split(",", 1)
        if len(tokens) == 1:
            return tokens[0], None
        elif len(tokens) == 2:
            return tokens[0], tokens[1]
        else:
            raise Exception("Flowbit parse error on %s" % (flowbit))

def enable_flowbit_dependencies(rulemap):
    """Helper function to resolve flowbits, wrapping the FlowbitResolver
    class. """
    resolver = FlowbitResolver()
    return resolver.resolve(rulemap)

def format_sidmsgmap(rule):
    """ Format a rule as a sid-msg.map entry. """
    return " || ".join([str(rule.sid), rule.msg] + rule.reference)

def format_sidmsgmap_v2(rule):
    """ Format a rule as a v2 sid-msg.map entry.

    eg:
    gid || sid || rev || classification || priority || msg || ref0 || refN
    """
    return " || ".join([
        str(rule.gid), str(rule.sid), str(rule.rev),
        "NOCLASS" if rule.classtype is None else rule.classtype,
        str(rule.priority), rule.msg] + rule.reference)



