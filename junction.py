#!/root/pypy-6.0.0-linux_x86_64-portable/bin/pypy
# -*- coding: utf-8 -*-
from __future__ import division
import codecs
import os
import sys
import paramiko
from optparse import OptionParser,SUPPRESS_HELP
import ConfigParser
import io
import getpass
import lib
import time
import logging
from logging.config import fileConfig
from collections import OrderedDict
import filelock
import smbc
import stat
import xmltodict
from tqdm import tqdm
from hurry.filesize import size
from ldap3 import Server, Connection, SUBTREE, ALL, NTLM
import configparser
import stat as stats
from kitchen.text.converters import getwriter
import subprocess
import ushlex as shlex
import pexpect
import datetime
import dns.resolver

# Patch for problem with the TQDM Library
tqdm.get_lock().locks = []

commands=["sdel",
"grpchange",
"list",
"ver",
"sadd",
"validate",
"rights",
"usageover",
"password",
"statuscodes",
"commands",
"srvadd",
"srvdel",
"rebuild",
"destvolume",
"quota",
"rename",
"connections",
"check",
"cluster",
"keytab"]
errorlist={
0:"STATUS 0 (Program exited successfully)",
10:"ERROR 10 (One or more errors in validate)",
11:"ERROR 11 (Usage Percentage Missing)",
20:"ERROR 20 (Failed LDAP connection to EDIR Server '{}')",
21:"ERROR 21 (Server '{}' amd Share '{}' not found in edir ldap)",
25:"STATUS 25 (Rename of Group assigned to junction '{}')",
30:"ERROR 30 (0 length password entered)",
31:"ERROR 31 (Mandatory command line option missing)",
32:"ERROR 32 (Junction config file not found '{}')",
34:"ERROR 34 (No junctions in '{}' to validate)",
35:"ERROR 35 (No '{}' found)",
36:"ERROR 36 (Config file missing '{}')",
40:"ERROR 40 (NSS path '{}' not found)",
41:"ERROR 41 (Delete folder aborted)",
42:"ERROR 42 (Invalid entry in '{}')",
45:"ERROR 45 (Server '{}' already in server list)",
46:"ERROR 46 (Server list '{}' not found)",
47:"ERROR 47 (Server '{}' not found via ping)",
48:"ERROR 48 (Server '{}' not in '{}')",
49:"ERROR 49 (No Server specified in Command '-n servernname')",
50:"ERROR 50 (Destination directory '{}' already exists)",
51:"ERROR 51 (Destination volume or server not found)",
52:"ERROR 52 (Destination Directory '{}' does not exist)",
53:"ERROR 53 (Failed to Create Junction {})",
54:"STATUS 54 (Junction '{}' exists and rights '{}' are correct)",
55:"ERROR 55 (Junction '{}' delete failed)",
56:"STATUS 56 (Junction '{}' delete succeeded)", 
57:"STATUS 57 (Junction Target '{}' created and rights '{}' have been assigned)",
58:"STATUS 58 (Junction {} rights correct)",
59:"ERROR 59 (Junction '{}' rights '{}' not set)",
60:"ERROR 60 (Group '{}' not found in AD)",
61:"ERROR 61 (Incorrect path format '{})",
62:"ERROR 62 (Incorrect Junction name '{}'(check case matches))",
63:"ERROR 63 (Group Format Error group '{}' should be DOMAIN\\\\group) ",
64:"ERROR 64 (No Group '{}' found in AD or server down)",
65:"ERROR 65 (Junction '{}' not found in '{}')",
66:"ERROR 66 (Error setting NSS Quota {} for target path '{}')",
67:"STATUS 67 (Group '{}' found in AD Forest '{}')",
68:"ERROR 68 (Quota '{}' needs to be a number)",
70:"ERROR 70 (Ping failed for server '{}')",
71:"ERROR 71 (LDAP down for server '{}')",
72:"ERROR 72 (EDIR LDAP timeout for '{}'",
79:"STATUS 79 (Junction '{}' does not exist in '{}')",
80:"ERROR 80 (Junction '{}' already exists according to '{}')",
81:"ERROR 81 (LDAP AD User Name '{}' or password incorrect (check junction.conf file)",
82:"ERROR 82 (Junction Name not found '{}')",
83:"ERROR 83 (Junction missing '{}')",
84:"ERROR 84 (VFS Access Error)",
85:"ERROR 85 (Target Folder Does Not Exist)",
86:"ERROR 86 (Junction '{}' already exists on all DFSROOT Servers)",
90:"ERROR 90 (Target path '{}' Not found)",
91:"ERROR 91 (Error Reading Directory '{}' (CIFS Connection failed))",
92:"ERROR 92 (No options on the commandline)",
93:"ERROR 93 (Mandatory Option missing from commandline)",
94:"ERROR 94 (Invalid update parameter (-u can only be yes or no))",
100:"ERROR 100 (OES Server '{}' not joined to AD)",
101:"ERROR 101 (DFS Root Server add aborted by user)",
102:"ERROR 102 (Junctions Missing from DFS Root '{}')",
103:"STATUS 103 (Trustee '{}' not found)",
104:"STATUS 104 (Trustee '{}' removed from '{}')",
110:"STATUS 110 (Connection Check Started)",
111:"STATUS 111 (Connection Check Completed)",
112:"ERROR 112 (No Linux permissions to run connection Check on '{}')",
120:"STATUS 120 (Check of Junction list file '{}' started)",
121:"ERROR 121 (Error '{}' in line '{}' of '{})",
122:"STATUS 122 (Check of Junction List file '{}' completed)",
130:"STATUS 130 (Cluster Check Started)",
131:"STATUS 131 (Cluster Check Finished)",
132:"ERROR 132 (No Cluster Detected at '{}')",
140:"STATUS 140 (Group Change started for '{}')",
141:"STATUS 141 (Group Change finished)",
150:"STATUS 150 (Rename of junction '{}' to '{}' completed on '{}')",
151:"ERROR 151 (Rename of junction '{}' to '{}' not completed on '{}' (VALIDATE WILL NEED TO RUN)",
152:"ERROR 152 (Rename source junction '{}' not founfd or destination '{}' already exists)",
161:"ERROR 161 (Target rights incorrect)",
162:"ERROR 162 (Trustee '{}' not found in AD)",
163:"ERROR 163 (Rights Assignment error)",
164:"ERROR 164 (Error Listing folder (is volume not mounted or folder does not exist)",
165:"ERROR 165 (Error in Rebuild of master.lst from server '{}')",
166:"ERROR 166 (Invalid option value '-o {}')",
170:"STATUS 170 ( Adding '{}' to list of DFS Root Servers)",
171:"STATUS 171 ( Added '{}' to list of DFS Root Servers)",
172:"ERROR 172 ('{}' not found in DNS)",
173:"ERROR 173 (Ip Address of '{}' '{}' needs to be added to '{}' in DNS)",
174:"STATUS 174 (CIFS Share '{}' already exists on server '{}')",
175:"ERROR 175 (CIFS Share '{}' does not exit on server '{}')",
176:"STATUS 176 (Creating CIFS Share '{}' on server '{}')",
177:"ERROR 177 (Server '{}' is already in '{}')",
178:"STATUS 178 (All CIFS Settings for '{}' already done)",
179:"ERROR 179 (Copy of vol.keytab failed for '{}')",
180:"STATUS 180 (One or more cifs config commands run on '{}')",
190:"STATUS 190 (Creating new keytab)",
191:"ERROR 191 (KVNO Missing from AD account '{}' spn may not be set correctly)",
192:"STATUS 192 (SPN '{}' found assigned to AD Account '{}')",
193:"ERROR 193 (SPN Missing from AD account '{}' setspn needs to be run from AD)",
194:"STATUS 194 (Checking SPN and KVNO for AD Account '{}')",
200:"ERROR 200 (Trustee '{}' missing from '{}')",
201:"ERROR 201 ('{}' rights incorrect on '{}')",
202:"STATUS 202 (Trustee '{}' correct for '{})",
203:"STATUS 203 (Directory '{}' created successfully)",
204:"STATUS 204 (Rights assigned to '{}' for '{}' are correct '{}')",
205:"STATUS 205 (Junction '{}' repaired)",
206:"ERROR 206 (Volume '{}' Not NSSAD Enabled)",
207:"STATUS 207 (No Trustee Assigned to folder '{}')",
210:"STATUS 210 (Rebuild of Master Junction List Started  to '{}' from '{}')",
211:"STATUS 211 (Rebuild of Master Junction List Complete '{}')",
212:"STATUS 212 ('{}' lines written to '{}' from '{}')",
213:"ERROR 213 (Errors Detected in '{}' from '{}')",
220:"ERROR 220 (KVNO Not found in AD)",
221:"ERROR 221 (NCP Volume '{}' not found on '{}')",
222:"STATUS 222 (Keytab file '{}' created)",
223:"ERROR 223 (Keytab file '{}' does not exist, run junction -o keytab)",
224:"STATUS 224 (Server '{}' added to '{}')",
250:"STATUS 250 (Junction Validation Underway)",
251:"STATUS 251 (Junction Validation Completed)",
252:"ERROR 252 (Number of Junctions on '{}' '{}' '{}' reports '{}')",
260:"STATUS 260 (Report Written to '{}')",
261:"ERROR 261 (Invalid Report Type '{}' specified [html/csv])",
270:"ERROR 270 (All DFS Root Servers not responding to ping)",
271:"ERROR 271 (CIFS Authentication Error to '{}' using account '{}')",
272:"ERROR 272 (CIFS Authentication Error to '{}' (unknown cause))",
280:"STATUS 280 (Destination Volume Check Underway)",
281:"STATUS 281 (Destination Volume Check Completed)",
282:"ERROR 202 (Destination Volume check report name missing from '{}')",
300:"ERROR 300 (General DFS Error with junction '{}')",
400:"ERROR 400 (Folder '{}' is not a junction)",
500:"STATUS 500 (Quota of {} set on {})",
501:"ERROR 501 (Error setting quota on {})",
}

def listvol(srv,user,pw):
	
	
	"""List Volumes via _ADMIN"""
	listvol=[]
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/manage.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmdstring="""<nssRequest>
		<volume>
			<listVolumes type="nss"/>
		</volume>
	</nssRequest>"""
	if debug=="yes":
		print cmdstring
	temp=nssfunc(cmdstring,file)
	result=xmltodict.parse(temp)
	
	volist=result["nssReply"]["volume"]["listVolumes"]["volumeName"]
	try:
		listvol.append(volist["#text"])
	except:
		for line in volist:
			listvol.append(line["#text"])
	return listvol
	
	

def dnscheck(host):
	resp=[]
	try:
		answers = dns.resolver.query(host, 'A')
	except:
		resp.append("-1")
		return resp
	
	for line in answers:
			line=str(line).replace("<DNS IN A rdata: ","")
			line=line.replace(">","")
			resp.append(line)
	return resp

def clusterlookup(srv,pw):
	cluster={}
	
	flt='(cn=*_MGT_GRP)'
	grplist=ldapfind(ldapsrv,"groupOfNames","*",srvbasecontext,["cn","objectClass","member"],flt,"cn=admin,o=home",pw1[1])
	for line in grplist:
		temp=[]
		
		clustername=line["attributes"]["cn"][0].replace("_MGT_GRP","")
		
		for line1 in line["attributes"]["member"]:
			member=line1.replace("cn=OESCommonProxy_","").split(",")[0]
			temp.append(member)
		cluster[clustername]=temp
	return cluster

def adspn(srv,basedn,obj,spn,user,pw):
	"""Check whether SPN has been set against AD object"""
	flt='(&(objectClass=User)(cn='+obj+'))'
	
	
	srv=ldapfind(srv,obj,"*",basedn,["cn","servicePrincipalName"],flt,user,pw)
	spn=srv[0]["attributes"]["servicePrincipalName"]
	adspn1=principal.replace("@"+domain.upper(),"")
	
	if adspn1 in spn:
		logstatus(192,adspn1,obj)
		return 0
	else:
		logstatus(193,adspn1,obj)
		return -1
	return

def kvnocheck(srv,basedn,obj,user,pw):
	"""Return KVNO from AD"""
	flt='(&(objectClass=User)(cn='+obj+'))'
	
	
	srv=ldapfind(srv,obj,"*",basedn,["cn","msDS-KeyVersionNumber"],flt,user,pw)
	try:
		kvno=int(srv[0]["attributes"]["msDS-KeyVersionNumber"])
	except:
		logstatus(220)
		shutdown(220)
	
	
	return kvno

def cluster(srv,user,pw):
	"""OES cluster state"""
	clusterdef={}
	srv=srv.replace("\n","")
	temp,error=remotecmd("cat /admin/Novell/Cluster/ResourceState.xml ",srv,user,pw)
	xml="".join(temp)
	
	clusterstat=xmltodict.parse(xml)
	resources=clusterstat["ncsReply"]["resources"]["resource"]
	nodestate,error=remotecmd("cat /admin/Novell/Cluster/NodeState.xml",srv,user,pw)
	nodestate="".join(nodestate)
	nodestate=xmltodict.parse(nodestate)
	clusterstate=nodestate["ncsReply"]["cluster"]
	clusterdef={clusterstate["name"]:clusterstate["nodes"]}

	
	return resources,clusterdef

def checkjlist(name):
	"""Functional Check of junction list"""
	for count,line in enumerate(name):
		item=line.split(",")
		if line in dupcheck.keys():
			errors.append(count+1,"Duplicate Line "+item[0])
			logstatus(121,"Duplicate Line",count+1,fname)
		stat=uncpathcheck(item[0])
		if stat==-1:
			errors.append([count+1,"UNC path invalid for "+item[0]])
			logstatus(121,"Invalid UNC path",count+1,fname)
		if domain not in item[1]:
			errors.append([count+1,"Domain Name of target invalid for "+item[0]])
			logstatus(121,"Invalid DNS Name",count+1,fname)
		stat=uncpathcheck(item[2])
		if stat==-1:
			errors.append([count+1,"Destination path error for "+item[0]])
			logstatus(121,"Invalid Destination Path",count+1,fname)
		if "\\\\" not in item[3]:
			errors.append([count+1,"Group error for "+unicode(item[0],"utf8")])
			logstatus(121,"Invalid Group",count+1,fname)
	errnum=str(len(errors))
	if errnum<>"0":
		print
		print "Error list for Filename "+fname
		print
		formatting="{:<40}{:<40}"
		print formatting.format("LINE","ERROR")	
		print
		for line in errors:
			print formatting.format(line[0],line[1].encode("utf8"))
	
	print
	print "Number of Errors "+errnum
	print
	return(errnum)
	
def uncpathcheck(path):
	temp=path.split("/")
	if len(temp)>0:
		if temp[0]<>'':
			return -1
		else:
			return 0
	else:
		return -1

def keytabupdate(ctx,server,dfsalias):
	#print server,ciffshare
	"""Linux copy and merge master copy of keytab"""
	dest="/tmp/vol.keytab"
	path="smb://"+server+"/"+ciffshare+"/._NETWARE/vol.keytab"
	new="smb://"+server+"/"+ciffshare+"/._NETWARE/vol.old"
	try:
		cifs_copy(ctx,path,dest)
	except:
		logstatus(179,server)
		shutdown(179)
	cifs_copy_back(dest,ctx,new)
	
	os.system("chmod 777 "+dest)
	os.system("klist -k "+dest)
	prompt="ktutil:"
	child=pexpect.spawn("ktutil")
	i=child.expect([prompt,prompt],timeout=3)
	args="rtk "+dest
	child.sendline(args)
	args="rkt "+adKeytabName
	child.sendline(args)
	child.sendline('write_kt ' + dest)
	child.sendline("quit")
	child.close()
	print "Check following KLIST output that it includes cifs/"+dfsalias
	print
	
	os.system("klist -k "+dest)
	print dest,path
	try:
		cifs_copy_back(dest,ctx,path)
	except:
		logstatus(179,server)
		shutdown(179)
	return	
	
	
def keytabcreate(filename,principal,domain,kvno,password):
	"""Linux Automate Creation of Keytab"""
	
	if os.path.isfile(filename):
		os.system("chmod 777 "+filename)
		os.system("rm "+filename)
	prompt="ktutil:"
	child=pexpect.spawn("ktutil")
	i=child.expect([prompt,prompt],timeout=3)
	args="addent -password -p "+principal+" -k "+kvno+" -e aes256-cts-hmac-sha1-96"
	child.sendline(args)
	child.sendline(password)
	child.sendline('write_kt ' + filename)
	child.sendline("quit")
	child.close()
	return filename
	
	
	
def volused(ctx,srv,volname):
	""" Volume used stats"""
	
	file=ctx.open ("smb://"+srv+"/_admin/Manage_NSS/Volume/"+volname+"/VolumeInfo.xml", os.O_CREAT | os.O_RDWR)
	temp=xmltodict.parse(file)
	if debug=="yes":
		print temp
	
	volfree=temp["nssReply"]["volumeInfo"]["percentAvailableSpace"].split(" ")[0]

	return(volfree)
	

def return_utf(s):
    if isinstance(s, str):
        return s.encode('utf-8')
    if isinstance(s, (int, float, complex)):
        return str(s).encode('utf-8')
    try:
        return s.encode('utf-8')
    except TypeError:
        try:
            return str(s).encode('utf-8')
        except AttributeError:
            return s
    except AttributeError:
        return s
    return s

def htmlheader(repheading,colheadings):
	"""Standard HTML Report Header"""
	charset="UTF-8"
	status.write("<html>\n")
	status.write("<head>\n")
	status.write("<meta http-equiv='content-type' content='text/html; charset=UTF-8'>")
	status.write("<style>\n")
	status.write("h1 {\n")
	status.write("\tfont-family: Arial;\n")
	status.write("}\n")
	status.write("table {\n")
	status.write("\tborder-collapse: collapse;\n")
	status.write("}\n")
	status.write("table,th,td {\n")
	status.write("\tborder: 1px solid black;\n")
	status.write("\tpadding: 15px;\n")
	status.write("\ttext-align: left;\n")
	status.write("}\n")
	status.write("th {\n")
	status.write("\tbackground-color: grey;\n")
	status.write("\tcolor: white;\n")
	status.write("\theight: 50px;\n")
	status.write("}\n")
	status.write("tr:hover{background-color:#f5f5f5}\n")
	
	status.write("</style>\n")
	status.write("<h1>"+repheading+"</h1>")
	status.write("<body>")
	status.write("<br>")
	tmp="Report Created on "+time.strftime("%c")
	status.write(tmp)
	
	status.write("<br><br>")
	status.write("<div style='overflow-x:auto';>\n")
	status.write("<table style='width:85%' border='2'>")
	status.write("<tr>\n")
	for col in colheadings:
		status.write("<th>"+col+"</th>")
	status.write("</tr>\n")
	return

def htmlbody(content,footer=[]):
	"""Standard Report Body"""
	for line in content:
		status.write("<tr>")
		for item in line:
			try:
				status.write("<td style='font-weight:bold;'>"+item+"</td>")
			except:
				item=unicode(item,"utf8")
				status.write("<td style='font-weight:bold;'>"+item+"</td>")
		status.write("</tr>")
	status.write("</table>\n")
	status.write("</div>\n")
	status.write("<br>")
	
	for line1 in footer[1:]:
		status.write("<H2>"+line1[0]+"<H2>")
	status.write("</body>")	
	status.close()
	return
	
	
	
def ldapfind(ldapsrv,obj,name,base_dn,attrs,flt,user,passw):
	"""Ldap Search Routine"""
	
	
	s = Server(ldapsrv, port = 636, use_ssl = True)
	try:
		c = Connection(ldapsrv,user=user, password=passw,auto_bind=True)
	except:
		
		logstatus(20,ldapsrv)
		shutdown(20)
	
	
	c.search(search_base = base_dn,search_filter = flt,search_scope = SUBTREE,attributes = attrs)
	
	return c.response

def volist(server,username,pw,baseou):
	"""lookup table of volume ncp mountpoints"""
	volumes={}
	obj="Volume"
	s = Server(server, port = 636, use_ssl = True)
	flt='(&(objectclass=volume)(cn=*))'
	attributes1=["cn","linuxNCPMountPoint"]
	try:
		c = Connection(server,user=username, password=pw,auto_bind=True)
	except:

		logstatus(20,server)
		shutdown(20)
		
	c.search(search_base = baseou,search_filter = flt,search_scope = SUBTREE,attributes = attributes1)
	for entry in c.response:
		try:
			mp=entry["attributes"]["linuxNCPMountPoint"][0]
		except:
			continue
		voldn=entry["dn"]
		volcn=voldn.split(",")
		volcn=volcn[0].replace("cn=","")
		
		if mp[0:4]=="EXT3":
			pass
		else:
			volumes[volcn]=mp.replace("NSS     ","")
	
	
	return volumes
	
	
def singlesearch(server1,username,pw,baseou,obj,cn,attributes1):
	"""Search for a unique object in AD"""
	items=[]
	server = Server(server1,port = 389,get_info=ALL)
	c = Connection(server,user=username, password=pw,auto_bind=True)
	c.search(search_base = baseou,search_filter = '(&(objectClass='+obj+')(cn='+cn+'))',search_scope = SUBTREE,attributes = attributes1)
	
	try:
		items.append(c.response[0]["attributes"]["cn"])
	except:
		pass
	return(items)
	
def ldapsearch(server1,username,pw,baseou,obj,attributes1,pages=5):
	""" AD ldap AD paged search"""
	items=[]
	total_entries = 0
	server = Server(server1,port = 389,get_info=ALL)

	try:
		c = Connection(server,user=username, password=pw,auto_bind=True)
	except:
		return items
	c.search(search_base = baseou,search_filter = '(objectClass='+obj+')',search_scope = SUBTREE,attributes = attributes1,paged_size = pages)
	total_entries += len(c.response)
	for entry in c.response:
		
		try:
			temp=entry["attributes"]["cn"]
			items.append(temp)
		except:
			pass
	cookie = c.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
	
	while cookie:
		c.search(search_base = baseou,search_filter = '(objectClass='+obj+')',search_scope = SUBTREE,attributes = attributes1,paged_size = pages,paged_cookie = cookie)
		total_entries += len(c.response)
		cookie = c.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
		for entry in c.response:
			try:
				temp=entry["attributes"]["cn"]
				items.append(temp)
			except:
				pass

	return items


def runloop(temp,count,ctx):
	"""Runloop for rebuild"""
	
	for count,line in enumerate(tqdm(temp),1):
		if "._" in line or "Icon" in line:
			count+-1
			continue
		if ".txt" not in line:
			if line not in defaultdirs:
				temp,rights=juncdest(server,ciffshare,line,srvlist1,ctx)
				
				if rights=="e":
					rights="NONE"
				if temp=="error":
					if debug=="yes":
						print server,ciffshare,line
						print temp,rights
					logstatus(400,line)
					count+-1					
					continue
				new1="/"+juncvol+"/"+line+","+temp[0]+"."+domain+",/"+temp[1]+"/"+temp[2]+","+rights.replace("\\","\\\\")+"\n"
				masterconfnew.write(new1)
				
				
	return count

def cifsjunc(server,jpath,tvol,tpath,username,password,rights,group):
	"""CIFS Create of Junction as a seperate callable routine"""
	rows,cols=checkscreen()
	share=tpath.split("/")[1]
	server1=server
	server=tvol
	
	# Check AD for Group
	result=adgroup(aduser,pw3[1],domain,group,adsearchbase)
	ctx=smbc.Context(auth_fn=auth_fn)
	
	volume1,path=volumes(tpath)
	
	volumename=tpath.split("/")[1]
	
	# Creates dest folder if does not exist
	stat=folder(ctx,"smb://"+tvol+"/"+volume1,path.replace("/",""))
	#print stat
	if stat==-1:
		mkdir(ctx,path.replace("/",""))
	else:
		#logstatus(57,(targetfolder,rights_dest.upper()))
		logstatus(52,targetfolder)
		
	#Lookup of NCP items from CIFS paths
		
	destserver=cifsnov(tvol,volumename)
	novvol=destserver["clustervol"][0].split(",")
	volume1=novvol[0].split("_")[1]
	
	fullpath="/media/nss/"+volume1.upper()+path	
	path=path.replace("/",":\\")
	path=volume1.upper()+path
	
	targetedir=destserver["clustervol"][0]
	targetedir=ndap(targetedir)
	# Set rights to the destination
	
	stat=addrights(tvol,path,rights,group)
	if stat<>"0":
		print "Error in rights assignment"
	#set junction target attributes
	setfileinfo(tvol,volume1,path)
	logstatus(57,(targetfolder,rights_dest.upper()))	
	path1=server
		
			
	volumename=jpath.split("/")[1]
	juncsource=cifsnov1(server1,volumename,srvlist1)
		
	mp=findmp1(juncsource["clustervol"][0],pw1[1])
	volume=ndap(juncsource["clustervol"][0])
			
			
	temp=tpath.split("/")
	tpath1="/"+temp[-1]
	fld=jpath.split("/")[-1]
	mp=mp+"/"+fld
			
	# Call Create Junction
	volume=volume.split(".")[0].split("_")[1]
	volume=volume+":\\"+fld
			
	stat=createjunc(mp,targetedir,tpath1,group,server1)
	stat=addrights(server1,volume,rights,group)
	return stat
	
				
			
        
	

def usage(junclist):
	"""Usage of individual junctions """
	print "Please Wait.."
	for line in junclist:
			temp=line.split(",")
			jpath=temp[0]
			server=temp[1].replace("\n","")
			path=temp[2]
			#print path
			destserver=cifsnov(server,path.split("/")[1],srvlist1)
			novvol=destserver["clustervol"][0].split(",")
			volume1=novvol[0].split("_")[1]
			path=volume1+":\\"+path.split("/")[-1]
			#print path
			fldinfo=folderinfo(path,server)
			used=fldinfo[2]
			quota=fldinfo[1]
			#print fldinfo
			if quota=="9223372036854775807":
				free="0"
				quota1=0
			else:
				if fldinfo[2]<>"0":
					quota1=int(fldinfo[1])
					inuse1=int(fldinfo[2])
					free1=(quota1/inuse1)
					free=100/free1
				
				else:
					free=0
					quota1=0
		
		
		
			if quota1>free:
				print "Junction Dest Server\t:"+server
				print "Junction Path\t\t:"+jpath
				print "Junction Dest Path\t:"+path
				print "Percentage Utilisation\t:"+str(free)+"%"
				print "="*cols
				print



def cifsconfig(srv,user,pw):
	"""Return CIFS Config stats from named oes server"""
	config={
	"DFS Suffix":"",
	"DFS Enable":"",
	"SMB Sig":"",
	"AD Joined":"",
	}
	temp1=[]
	temp=remotecmd("novcifs -o",srv,user,pw)
	dfssuffix=filter(lambda x: "DNS suffix for DFS referral" in x, temp[0])
	dfs=filter(lambda x: "DFS" in x, temp[0])
	sig=filter(lambda x: "SMB signature" in x, temp[0]) 
	config["DFS Suffix"]=dfssuffix[0].split(" - ")[1].replace("\n","").replace(" ","")
	config["DFS Enable"]=dfs[0].split(" - ")[1].replace("\n","").replace(" ","")
	config["SMB Sig"]=sig[0].split(" - ")[1].replace("\n","").replace(" ","")
	

	temp=remotecmd("nitconfig get",srv,user,pw)
	adjoined=filter(lambda x: "ad-joined-domain" in x, temp[0])
	config["AD Joined"]=adjoined[0].split("=")[1].replace("\n","")
	return config

def cifsset(srv,user,pw,config):
	"""Setup CIFS to support DFS"""
	cmd=""
	if config["DFS Suffix"]=="":
		cmd="novcifs --dns-suffix="+dnssuffix+"\n"
	if config["DFS Enable"]<>"Enabled":
		cmd=cmd+"novcifs --dfs-support=yes\n"
	if config["SMB Sig"]<>"Optional":
		cmd=cmd+"novcifs --enable-smbsigning=optional\n"
	if cmd=="":
		logstatus(178,server)
	else:
		temp=remotecmd(cmd,srv,user,pw)
		logstatus(180,srv)
		print
		print "The following commands have been run"
		print cmd
	if config["AD Joined"]=="":
		logstatus(100,srv)
		


def checkscreen():
	"""Return termninal screen size"""
	rows, columns = os.popen('stty size', 'r').read().split()

	return (int(rows),int(columns))

def createshare(srv,sharename,path):
	"""Create Named CIFS Share on OES Server"""
	print path
	path=path.upper()
	if ":/" not in path:
		path=path+":/"
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/manage.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmdstring="""<nssRequest>
		<cifs>
			<addShare>
				<shareName><![CDATA["""+sharename+"""]]></shareName>
				<pathName><![CDATA["""+path+"""]]></pathName>
				<comment> <![CDATA[DFS Root Share Created by Junction]]></comment>
			</addShare>
		</cifs>
	</nssRequest>"""
	if debug=="yes":
		print cmdstring
	temp=nssfunc(cmdstring,file)
	result=xmltodict.parse(temp)
	
	code=result["nssReply"]["cifs"]["addShare"]["result"]["@value"]
	return code
	
	

def juncdest(srv,volume,path,lookup,ctx):
	"""Find the junction destination from the source"""
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/manage.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	
	srvname=srv.split(".")[0].upper()
	line=filter(lambda x: srvname in x["attributes"]["cn"], srvlist1)
	#print line[0]["attributes"]
	
	volmap=line[0]["attributes"]["nfapCIFSShares"].split("$")

	line1=filter(lambda x: volume.lower() in x.lower(),volmap)
        if len(line1)==0:
		return "error","error"
			
	cifs=line1[0].split(" ")
	ncp=cifs[0].replace("'","").replace(":","")
	
	cmdstring="""<nssRequest>
	<dfs>
		<readLink>
			<pathName><![CDATA["""+ncp+":"+path+"""]]></pathName>
		</readLink>
	</dfs>
</nssRequest>"""
	temp=nssfunc(cmdstring,file)
	result=xmltodict.parse(temp)
	
	status=result["nssReply"]["dfs"]["readLink"]["result"]["@value"]
	if status=="1006":
		logstatus(300,srv+":/"+ncp+"/"+path)
		shutdown(300)
		
	if status=="0":
		volumeinfo=result["nssReply"]["dfs"]["readLink"]["junction"]["volumeInfo"]
		servername=volumeinfo["server"]
		volname=volumeinfo["volumeName"]
		path=result["nssReply"]["dfs"]["readLink"]["junction"]["path"]
	else:
		servername="error"
		volname="error"
		path="error"
	
	if servername<>"error":
		servername=servername.split(".")[0]
	else:
		return "error","error"
		
	line=filter(lambda x: servername in x["attributes"]["nfapCIFSServerName"], srvlist1)
	
	volmap=line[0]["attributes"]["nfapCIFSShares"].split("$")
	line1=filter(lambda x: volname in x,volmap)
	
	cifsh=line1[0].split(" ")
	cifsh=cifsh[1].replace("'","").replace(":","").replace("\\24","")

	
	temp=folderinfo(volname.upper()+":\\"+path,servername.lower()+"."+domain.replace("\n",""))
	group=temp[0][0][0]
	
	destinfo=[servername.lower(),cifsh.lower(),path]
	
	del file
	return destinfo,group
	
def rights(srv,volume,path,rights_dest,group):
	"""Query of rights on Volume"""
	
	start=time.time()
	g=1
	r=1
	#print volcache
	if debug=="yes":
		print srv,path,rights_dest,group
		print volume
		
	sortedrights=''.join(sorted(rights_dest))
	volume=volume.replace(":\\","")
	tempath=path.split("/")
	if len(tempath)>1:
		path="/"+tempath[-1]
	if srv in volcache.keys():
		state="cached"
		
		
	else:
		state="notcached"
		#print srv,volume
		context="smb://"+srv+"/_admin/Manage_NSS/Volume/"+volume+"/TrusteeInfo.xml"
		try:
			tlist = ctx.open (context, os.O_CREAT | os.O_RDWR)
		except RuntimeError:
			logstatus(91,context)
			shutdown(91)
		
		tempfile=tlist.read()
		#print tempfile
		result=xmltodict.parse(tempfile)
		volcache[srv]={volume:result}
	

	temp1=volcache[srv][volume]["nssReply"]["trusteeInfo"]["file"]
	
	temp2=filter(lambda x: repr(x["path"])==repr(path), temp1)
	
	if len(temp2)>0:
		
		t2=temp2[0]["trustee"]
		
	else:
		r=1
		g=1
		return r,g
	t2type=str(type(t2))
	if "list" in t2type:
		if len(temp2)>0:
			temp4=temp2[0]["trustee"]
			groupname=group.split("\\")[-1].lower()
			if "\\\\" in group:
				group=group.replace("\\\\","\\")
			else:
				pass
			if groupname[:1]==" ":
				groupname=groupname[1:]
			temp3=filter(lambda x: x["name"].lower().endswith(groupname), temp4)
			try:
				assigned=temp3[0]["rights"]["@value"]
				trustee=temp3[0]["name"].lower()
			except:
				g=1
				r=1
				trustee=""
				assigned=""
		else:
			r=1
			g=1
			return r,g
			
	else:
		groupname=group.split("\\")[-1]
		assigned=t2["rights"]["@value"]
		trustee=t2["name"].lower()
		
	#print trustee
	if debug=="yes":
		print srv,path,rights_dest,group
		print "----"
		print volume
		print trustee,groupname
		print sortedrights,assigned
		try:
			print temp3
		except:
			print t2
		print "===================="
	done=time.time()
	
	if trustee.endswith(groupname.lower()):
			g=0
	assigned=''.join(sorted(assigned))
	#print sortedrights,assigned
	if sortedrights == assigned:
			r=0
	if r==0 and g==0:
			return(r,g)
	else:
		pass
		
	return	(r,g)		



			
		
def setfileinfo(srv,volume,path):
	"""Function to set delete inhibit and rename inhibit"""
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmdstring="""<fileRequest>
	<fileInfo>
		<setFileInfo>
		<fileName>"""+path+"""</fileName>
		<attributes>
			<renameInhibit enabled="yes"/>
			<deleteInhibit enabled="yes"/>
		</attributes>
		<symlink/>
		<nameSpace>LONG</nameSpace>
		</setFileInfo>
	</fileInfo>
</fileRequest>"""
	temp=nssfunc(cmdstring,file)
	result=xmltodict.parse(temp)
	result=result["fileReply"]["fileInfo"]["setFileInfo"]["result"]["description"]
	return	
	
def rights2(srv,volume,path,rights_dest,group):
	#path=volume+path.replace("/","")
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	print path	
	cmdstring="""<fileRequest>
	<fileInfo>
		<getFileInfo type="adID">
		<adOnly/>
		<idOnly/>
		<fileName>"""+path+"""</fileName>
		<symlink/>
		<nameSpace>LONG</nameSpace>
		<typeOfInfo type="adID">
			<rightsInfo type="adID"/>
			<idInfo type="adID"/>
		</typeOfInfo>
		</getFileInfo>
	</fileInfo>
</fileRequest>"""
	
	cmdstring1="""<fileRequest>
	<fileInfo>
		<getEffectiveRightsByUser type="adID">
		<includeADIdentities/>
		<name>novell\Domain Admins</name>
		<fileName>"""+path+"""</fileName>
		</getEffectiveRightsByUser>
	</fileInfo>
</fileRequest>"""
	print cmdstring
	temp=nssfunc(cmdstring,file)
	print temp
	sys.exit()
		
		
		
def delrights(srv,path,trustee):
	file1 = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file1.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmdstring="""<fileRequest>
	<trustees>
	<removeTrustee type="adID">
		<name>"""+trustee.replace("\n","")+"""</name>
		<fileName>"""+path+"""</fileName>
	</removeTrustee>
</trustees>
</fileRequest>
"""
	temp=nssfunc(cmdstring,file1)
	
	if debug=="yes":
		print cmdstring
		print temp
		
	result=xmltodict.parse(temp)
	
	stat=result["fileReply"]["trustees"]["removeTrustee"]["result"]["@value"]
	
	return stat
	





def addrights(srv,path,rights,trustee):
	"""Add Rights to an NSS Folder"""
	cmd=""
	
	rgts={"s":"supervisor","r":"read","w":"write","c":"create","e":"erase","a":"accessControl","f":"fileScan","m":"modify"}	
	for line in rights:
		try:
			parts=[cmd,"\t\t\t\t<",rgts[line]+"/>\n"]
			cmd="".join(parts)
			
		except:
			print "Invalid Rights"
			return "-1"
	cmd=cmd[:-1]
	
	file1 = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file1.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	path=path.encode("utf8")
	
	if "\\" not in trustee:
		logstatus(207,"//"+srv+path)
		stat="0"
		return stat

	cmdstring=u"""<fileRequest>
	<trustees>
		<addTrustee type="adID">
			<includeADIdentities type="adID"/>
			<name>"""+trustee+"""</name>
			<rights>
"""+cmd+u"""
			</rights>
			<fileName><![CDATA["""+unicode(path,"utf8")+"""]]></fileName>
			<nameSpace>Long</nameSpace>
			<symlink/>
		</addTrustee>
	</trustees>
</fileRequest>"""
	temp=nssfunc(cmdstring,file1)
	result=xmltodict.parse(temp)
	if debug=="yes":
		print cmdstring
		print temp
		print result
	stat=result["fileReply"]["trustees"]["addTrustee"]["result"]["@value"]
	return stat


def displayerrors():
	"""List Error/Status Codes"""
	print "Error/Status Codes"
	print "\n"
	for num,error in errorlist.iteritems():
		print num,error
	print "\n"

def logstatus(errnumber,*args):
	"""Reporting of Errors"""

	name=args
	errorprint=errorlist[errnumber]
	
	try:
		errorlog=logstat+" "+errorprint.format(*name)
		#print errorlog
		
		logger.info(errorlog)
	except:
		error="Undefined Errror"
	try:	
		print errorprint.format(*args)
	except:
		errorprint=unicode(errorprint,"utf-8")
		try:
			print errorprint.format(*args)
		except:
			print errorprint,args
	return


def exit_codes(errorlist):
	"""Prints all exitcodes"""
	print 
	print "EXIT CODES"
	print
	
	j=OrderedDict(sorted(errorlist.items()))
	for line in j.keys():
		print "["+str(line)+"]\t:"+errorlist[line]
	print
	return
	

def checkfldr(folder,server,volumename,group,user,pw,srvlist1):
	"""Check Folder and Rights with results caching"""
	# Check derived destination folder
	destserver=cifsnov(server,volumename,srvlist1)
	novvol=destserver["clustervol"][0].split(",")
	
	#volume=novvol[0].split("_")[1]+":\\"
	parts=[novvol[0].split("_")[1],":\\"]
	volume="".join(parts)
	mp=findmp(destserver["clustervol"][0],volcache)	
	try:
		path=mp+folder.replace("/"+volumename,"")
	except:
		folder=unicode(folder,"utf8")
		path=mp+folder.replace("/"+volumename,"")
	if "\\\\" in group:
		r,g=rights(server,volume,path,rights_junc,group)
	else:
		r=0
		g=0
	
	return(r,g)



def mkdir(ctx1,directory):
	"""Make a directory over cifs"""
	try:
		directory=directory.encode("utf8")
		ctx1.mkdir(directory,0)
		return(0)
	except:
		exc_info = sys.exc_info()
		print exc_info
		return (-1)

def folder(ctx,smbpath,fname):
	"""Check if folder exists and if not create it"""
	srv=smbpath.replace("smb://","").split("/")[0]
	ls=dir1(ctx,smbpath.replace("smb://",""))
	fname=unicode(fname,"utf8")
	if fname in ls:
		return(0)
	else:
		if destRequired.lower()=="yes" and op=="sadd":
			return(-1)
		smbpath=smbpath+"/"+fname
		
		try:
			status=mkdir(ctx,smbpath)
			return(0)
		except:
			exc_info = sys.exc_info()
			print exc_info
			return(-1)
		if status==0:
			return(0)
				
	return(-1)	
	


def readfile(lockfile,name,time=30):
	"""File Locking of a file read"""
	lock=filelock.FileLock(lockfile)
	try:
		lock.acquire(timeout=time)
	except filelock.Timeout:
		status=-1
		return(status,"")
	try:	
		dat=open(name,"r").readlines()
	except IOError:
		dat=open(name,"a+")
		dat.close()
		dat=open(name,"r").readlines()
	lock.release()
	return(0,dat)


def writefile(lockfile,name,content,time=30):
	"""File Locking of a file write"""
	lock=filelock.FileLock(lockfile)
	try:
		lock.acquire(timeout=time)
	except filelock.Timeout:
		return(-1)
	dat=open(name,"a+")
	for line in content:
		dat.write(line)
	lock.release()
	dat.close()
	return(0)

		

def dir1(ctx1,dirname):
	"""CIFS Directory"""
	dirname="smb://"+dirname
	try:
		ls=ctx1.opendir(dirname).getdents()
		
	except smbc.PermissionError:
		logstatus(271,dirname,ediruser)
		shutdown(271)
	except smbc.TimedOutError:
		logstatus(91,dirname)
		shutdown(91)
	except smbc.NoEntryError:
		logstatus(90,dirname)
		shutdown(90)
	except ValueError:
		logstatus(91,dirname)
		shutdown(91)
	except:
		print sys.exc_info()
		sys.exit()
	
	if debug=="yes":
		for line in ls:
			print line.name,line.smbc_type
		
	ls1=[line.name for line in ls]
	return(ls1)
	
def auth_fn(server, share, workgroup, username1, password1):
	"""Cifs Authentication Helper"""
	if debug=="yes":
		print workgroup,username,password
	return (workgroup, username, password)
	
	
	
	
def setquota(fname,quota,srv):
	"""Set NSS Quota"""
	
	quota=quota.replace("GB","")
	
	quota=int(quota)*1073741824
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmd="""<fileRequest>
			<directoryQuotas>
				<addQuota>
					<fileName>"""+fname+"""</fileName>
					<quotaAmount>"""+str(quota)+"""</quotaAmount>
				</addQuota>
				<symlink/>
			</directoryQuotas>
	</fileRequest>
"""
	temp=nssfunc(cmd,file)
	test=xmltodict.parse(temp)
	#print test
	status=test["fileReply"]["result"]["@value"]

	return(status) 
	

def folderinfo(fname,srv):
	""" Report on Selected Folder Meta Data"""
	fldinfo=[]
	acltemp=[]
	server=srv
	ctx=smbc.Context(auth_fn=auth_fn)
	u=1
	
	
	
	
	rgts={"supervisor":"s","read":"r","write":"w","create":"c","erase":"e","accessControl":"a","fileScan":"f","modify":"m"}	
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmdtemp="""<fileRequest>
	<fileInfo>
		<getFileInfo>
		<includeADIdentities type="adID"/>\n"""
	cmdtemp1="		<fileName>"+fname+"</fileName>\n"
	cmdtemp2="""		<nameSpace>Long<nameSpace/>
		<typeOfInfo>
			<rightsInfo/>
			<standardInfo/>
			<timeInfo/>
			<symLink/>
			<directoryQuotaInfo>
				<quotaAmount/>
				<usedAmount/>
			</directoryQuotaInfo>
		<idInfo/>
		</typeOfInfo>
	</getFileInfo>
	</fileInfo>
</fileRequest>"""
	
	
	cmd=cmdtemp+cmdtemp1+cmdtemp2
	if debug=="y":
		print cmd
	temp=nssfunc(cmd,file)
	
	test=xmltodict.parse(temp)
	#print test
	try:
		rights=test["fileReply"]["fileInfo"]["getFileInfo"]["rightsInfo"]["trusteeList"]["trusteeInfo"]
		quotamount=test["fileReply"]["fileInfo"]["getFileInfo"]["quotaInfo"]["quotaAmount"]
		usedamount=test["fileReply"]["fileInfo"]["getFileInfo"]["quotaInfo"]["usedAmount"]
		status=test["fileReply"]["fileInfo"]["getFileInfo"]["result"]["description"]
	except:
		rights="error"
		quotaamount="error"
		usedamount="error"
		status="error"	
	#print rights
	tlist=[]
	priv=""
	if rights=="error":
		return "error"
	if len(rights)<>4:
		for line in rights:
			#print line
			trustee=line["trustee"]
			acl=line["rights"]
		
			for tempacl in acl:
				priv=priv+rgts[tempacl].upper()
			acltemp1=[trustee,priv]
			priv=""
			acltemp.append(acltemp1)
	else:

		try:
			trustee=rights["trustee"]
			acl=rights["rights"]
		except:
			trustee=rights[0]["trustee"]
			acl=rights[0]["rights"]
		for tempacl in acl:
				priv=priv+rgts[tempacl].upper()
		acltemp1=[trustee,priv]
		acltemp.append(acltemp1)
		
	fldinfo=[acltemp,quotamount,usedamount,status]
	return fldinfo

def dircheck(fname,rights,trustee,srv):
	"""Rights Checking of an existing folder"""
	server=srv
	ctx=smbc.Context(auth_fn=auth_fn)
	u=1
	rgts={"supervisor":"s","read":"r","write":"w","create":"c","erase":"e","accessControl":"a","fileScan":"f","modify":"m"}	
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	cmdtemp="""<fileRequest>
	<fileInfo>
		<getFileInfo>
		<includeADIdentities type="adID"/>\n"""
	cmdtemp1="		<fileName>"+fname+"</fileName>\n"
	cmdtemp2="""		<nameSpace>Long<nameSpace/>
		<typeOfInfo>
			<rightsInfo/>
			<standardInfo/>
			<timeInfo/>
			<directoryQuotaInfo>
				<quotaAmount/>
				<usedAmount/>
			</directoryQuotaInfo>
		<idInfo/>
		</typeOfInfo>
	</getFileInfo>
	</fileInfo>
</fileRequest>"""
	
	
	cmd=cmdtemp+cmdtemp1+cmdtemp2
	if debug=="y":
		pass
		#print cmd
	temp=nssfunc(cmd,file)
	
	test=xmltodict.parse(temp)
	status=test["fileReply"]["fileInfo"]["getFileInfo"]["result"]["description"]
	if "success" in status:
		print "found"
		resp=test["fileReply"]["fileInfo"]["getFileInfo"]["rightsInfo"]["trusteeList"]["trusteeInfo"]
	else:
		print status
		u=1
		g=1
		return(g,r)
	
	for line in resp:
		if line["trustee"].lower()==trustee.lower():
			g=0
			rghts=line["rights"]
			shortright=""
			for item in rghts:
				shortright=shortright+rgts[item]
			shortright="".join(sorted(shortright))
			rights="".join(sorted(rights))
			#print rights,shortright
			if rights==shortright:
				print "rights match"
				r=0
				return(g,r)
			else:
				r=1
				return(g,r)
				
	r=1
	g=1
	return(g,r)
	


def vararg_callback(option, opt_str, value, parser):
	"""Helper Function for parameter handling"""
	assert value is None
	value = []

	def floatable(str):
		try:
			float(str)
			return True
		except ValueError:
			return False

	for arg in parser.rargs:
		# stop on --foo like options
		if arg[:2] == "--" and len(arg) > 2:
			break
		# stop on -a, but not on -3 or -3.0
		if arg[:1] == "-" and len(arg) > 1 and not floatable(arg):
			break
		value.append(arg)

	del parser.rargs[:len(value)]
	setattr(parser.values, option.dest, value)



def readrights(fname,rights,trustee,srv):
	"""read access rights """
	u=1
	rgts={"supervisor":"s","read":"r","write":"w","create":"c","erase":"e","accessControl":"a","fileScan":"f","modify":"m"}	
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/files.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	
	
	cmdtemp="""<fileRequest>
	<fileInfo>
		<getAllEffectiveRights>
			<includeADIdentities/>"""
	cmdtemp1="<fileName>"+fname+"</fileName>\n"
	cmdtemp2="""		</getAllEffectiveRights>
	</fileInfo>
</fileRequest>/n"""
	cmd=cmdtemp+cmdtemp1+cmdtemp2
	if debug=="y":
		print cmd
	temp=nssfunc(cmd,file)
	test=xmltodict.parse(temp)

	temp=test["fileReply"]["fileInfo"]["getAllEffectiveRights"]["allAccessRights"]["accessRights"]
	rights1=""
	for line in temp:
		
		if trustee.lower()==line["name"].lower():
			g=0
			print "Trustee Matched"
			print line["rights"]
			if line["rights"]<>None:
				for temp1 in line["rights"]:
					print temp1
					rights1=rights1+rgts[temp1]
				print "rights are "+rights1
			else:
				g=1
			if rights==rights1:
				r=0
				g=0
				break
			else:
				r=-1
				g=-1
		else:
			r=-1
			g=-1
			print "No rights assigned"
		print "======="
	return	g,r	

	

	
	

def ping(addr):
	"""Ping Command"""
	status=os.system("ping -c 1 "+addr+null)
	if status<>0:
		print "\t"+addr+"\t[Not Found]"
		logstatus(70,addr)
		shutdown(70)
		
	else:
		pass
	return(status)

def displayhelp():
	trim=60
	"""Options help screeen"""
	print "Junction Command Help"
	print "====================="
	print 
	print "junction -o destvolume [-f html]".ljust(trim)+":Destination Volume Usage Report"
	print "junction -o rights -j /vol/junc".ljust(trim)+":Rights of junction and the target"
	print "junction -o ver".ljust(trim)+":Junction Version"
	print "junction -o list [-f html]".ljust(trim)+":List Junctions"
	print "junction -o sdel -j /vol/junc".ljust(trim)+":Remove a junction from all servers"
	print "junction -o dir -t srv -p/vol/dir".ljust(trim)+":List an NSS directory"
	print "junction -o validate [-j /xx/xx] [-u yes][-a yes]".ljust(trim)+":Check on junctions"
	print "junction -o quota -j /vol/junc -q 30".ljust(trim)+":Set a directory quota"
	print "junction -o password".ljust(trim)+":Reset AD and EDIR Pssswords"
	print "Junction -o statuscodes [xx]".ljust(trim)+":List of Status/Exit Codes"
	print "junction -o srvadd srv.domain.com".ljust(trim)+":Add named server to dfs root group"
	print "junction -o srvdel srv.domain.com".ljust(trim)+":Del named server from dfs root group"
	print "junction -o rebuild -n srv.domain.com".ljust(trim)+":Rebuild master junction list from named server"
	print "junction -o report -f html/csv".ljust(trim)+":Create an html or csv report"
	print "junction -o rename -j /xx/old /xx/new".ljust(trim)+":Rename junction"
	print "junction -o connections".ljust(trim)+":CIFS Client connection details"
	print "junction -o check -c /xx/xx/xx/file".ljust(trim)+":Checks the contents of the master.lst file"
	print "junction -o grpchange -j /vol/junc".ljust(trim)+"-g domain\\group"
	print "junction -o keytab".ljust(trim)+":Create a keytab file"
	print "junction -o cluster".ljust(trim)+":Cluster Membership of DFSROOT Servers"
	print 
	print "junction -o sadd -j /vol/junc -t srv -p /vol/dir -g domain\\group -q xx(gb) -u yes/no"
	print
	print "-o sadd\t\t:Add junction to multiple servers"
	print "-j /vol/dir\t:CIFS Volume and junction name for the junction"
	print "-t srv.xx.com\t:DNS Name of virtual server that holds the junction target directory"
	print "-p /vol/dir\t:CIFS Volume and directory of the junction destination"
	print "-g domain\\\\grp\t:Group name for rights assignment"
	print "-q xxx\t\t:Quota in GB"
	print "-u yes/no\t:Ignore the list of previously created junctions"
	print "\n"
	print "Options for Validate"
	print "===================="
	print "-u yes: If u=yes then any missing junctions are added to all servers"
	print "-a yes: If a=yes then eny extra junctions will be removed"
	print "\n"
	

def displayresp(list):
	"""Format response from SSH request"""
	for line in list:
		line=line.replace("\n","")
		line=line.replace("\m","")
		print line
	return
	
def checkpath(path):
	"""Check path format """
	if op=="rename":
		return
	try:
		tmp=path.split("/")
	except:
		logstatus(61,path)
		shutdown(61)
		
	if len(tmp)<>3 and options.op<>"dir":
		logstatus(61,path)
		shutdown(61)
	
	return



def checklist(list1,query):	
	"""Check a list and return line that contains value"""
	
	line1 = filter(lambda x: x.split(",")[0]==query, list1)
	
	if len(line1)<>0:
		
		temp1=line1[0].replace("\n","").split(",")
		tvol=temp1[1]
		path=temp1[2]
		group=temp1[3]
		return tvol,path,group
	else:
		return None,None


			
def patch_crypto_be_discovery():

    """
    Monkey patches cryptography's backend detection.
    Objective: support pyinstaller freezing.
    """

    from cryptography.hazmat import backends

    try:
        from cryptography.hazmat.backends.commoncrypto.backend import backend as be_cc
    except ImportError:
        be_cc = None

    try:
        from cryptography.hazmat.backends.openssl.backend import backend as be_ossl
    except ImportError:
        be_ossl = None

    backends._available_backends_list = [
        be for be in (be_cc, be_ossl) if be is not None
    ]

def volmp(srv,volumename):
	"""EDIR for volume mountpoint"""
	juncsource=cifsnov(srv,volumename)
	tvol1=ndap(juncsource["clustervol"][0])
	mp=findmp(juncsource["clustervol"][0])
	return mp
	
	

def findmp(voldn,volcache):
	"""Find Volume Mountpoint from edir object"""
	volcn=voldn.split(",")
	volcn=volcn[0].replace("cn=","")
	
	
	mp=volcache[volcn]
	
	
	return mp	

	
def stripvol(vol):
	"""take the edir volume object and output the actual volume name"""
	vol=vol.split(",")[0]
	vol=vol.split("_")[1]
	return vol
	

def vserver(basedn,user,pw):
	"""Return in memory list of edir servers"""
	flt='(&(objectclass=ncpServer)(!(ldapServerDN=*)))'
	srv=ldapfind(ldapsrv,"ncpServer","*",basedn,["cn","objectClass","ncsNetWareCluster","nCSVolumes","nfapCIFSServerName","nfapCIFSShares","Resource"],flt,user,pw)
	#print srv
	return srv

def cifsnov(dnsname,volume,srvlist1):
	"""Build Lookup table from ldap results"""
	
	details={}
	name=dnsname.split(".")[0].upper()
	volume=volume.replace("$","\\24").upper()
	
	line1 = list(filter(lambda x: (x["attributes"]["nfapCIFSServerName"].upper()==name) and (volume in x["attributes"]["nfapCIFSShares"].upper()), srvlist1))
	
	
	if len(line1):
	
		details["clustername"]=line1[0]["attributes"]["ncsNetWareCluster"]
		details["clustervol"]=line1[0]["attributes"]["nCSVolumes"]
		details["cifshares"]=line1[0]["attributes"]["nfapCIFSShares"]
		details["resource"]=line1[0]["attributes"]["Resource"]
		details["cn"]=line1[0]["dn"]
		return details
	else:
	
		logstatus(21,name,volume)
		shutdown(21)

def uniquefname():
	"""Make a unique file name based on current Time"""
	timestr = "-"+time.strftime("%Y%m%d-%H%M%S")
	return timestr
	
def remmkdir(srv,path,user,pw):
	
	"""Create remote path on server"""
	cmd=cmdprefix+" mkdir \""+path+"\""
	out,error=remotecmd(cmd,srv,user,pw)
	if error==None:
		logger.info("Destination Directory "+path+" has been created")
		print "Destination Directory "+path+" has been created"
		return
	if error and upd<>"y":
		logstatus(50,path)
		shutdown(50)
	else:
		
		print "Update "+upd
	
	return
	

def checkgroup(grplist,grpname):
	"""Check AD group and process result"""
	ping(domain)
	
	result=grpcheck(grplist,grpname)
	# if group not found in ad then do not continue
	if result==-1:
		print
		logstatus(64, grpname)
		shutdown(64)
	else:
		print
		logstatus(67,grpname,domain)
		print
	return result

def shutdown(ex=0):
	"""Junction Shutdown routinte"""
	#print ex
	pid1=str(pid)
	
	print
	if ex<>0:
		print "ERROR Program Halted"
		logger.info(logstat+" ERROR  Program Halted with error")
	else:
		print "STATUS Program Completed"
		logger.info(logstat+" STATUS "+str(ex)+" Program Completed")
	try:
		#close.ctx()
		del ctx
		
	except:
		print
	sys.exit(ex)



def createcsv(srvlist):
	"""Creates CSV Report"""
	print
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
	try:
		uname=validatecsv
		now=time.strftime("%c")
		status=open(uname,"w")
	except:
		print "CSV File in use or path invalid"
		return(uname)
	
	status.write("\"Junction Name\",\"Junction Target\",\"Access Group\",")
	for line in srvlist:
		status.write("\""+line[:-1]+"\",")
	status.write("\n")
	
	for srv in srvlist:
		srv=srv[:-1]
		
		for temp in junclist:
			rowtemp=""
			temprow=temp.split(",")
			temp1=temp.split(",")[0]
			volume=temp1.split("/")[1]
			tpath=temprow[2]
			tsrv=temprow[1]
			group=temprow[3]
			linestart="\""+temp.split(",")[0]+"\",\""+tsrv+tpath+"\",\""+group+"\","
		
			lineend=""
			for line in srvlist:
				#lineend=""
				error="no"
				
				if error=="no":
					lineend=lineend+"\"OK\","
				error="no"
			lineend=lineend[:-1]+"\n"
			status.write(linestart+lineend)
			lineend=""

	return uname
	


def createtable(srvlist,ctx,server_dir,ciffshare):
	"""Creates HTML Status Page"""
	server=srvlist[0].replace("\n","")
	username=ediruser
	
	start_time=time.time()
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	if srvlist=="no":
		stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
	uname=validate
	now=time.strftime("%c")
	if os.path.isfile(uname):
		try:
			os.remove(uname)
		except OSError:
			print
			print "Existing File "+uname+" cannot be removed"
			print
	
	status=open(uname,"w")
	status.write("<html>\n")
	status.write("<head>\n")
	status.write("<meta http-equiv='content-type' content='text/html; charset=UTF-8'>")
	status.write("<style>\n")
	status.write("h1 {\n")
	status.write("\tfont-family: Arial;\n")
	status.write("}\n")
	status.write("table {\n")
	status.write("\tborder-collapse: collapse;\n")
	status.write("}\n")
	status.write("table,th,td {\n")
	status.write("\tborder: 1px solid black;\n")
	status.write("\tpadding: 15px;\n")
	status.write("\ttext-align: left;\n")
	status.write("}\n")
	status.write("th {\n")
	status.write("\tbackground-color: grey;\n")
	status.write("\tcolor: white;\n")
	status.write("\theight: 50px;\n")
	status.write("}\n")
	status.write("tr:hover{background-color:#f5f5f5}\n")
	
	status.write("</style>\n")
	status.write("<h1>Junction Status Report</h1>")
	status.write("<body>")
	status.write("<br>")
	tmp="Report Created on "+time.strftime("%c")
	status.write(tmp)
	
	status.write("<br><br>")
	status.write("<div style='overflow-x:auto';>\n")
	status.write("<table style='width:85%' border='2'>")
	status.write("<tr>\n")
	status.write("<th>Junction Name</th>")
	status.write("<th>Junction Target</th>")
	status.write("<th>Access Group</th>")
	for line in srvlist:
		status.write("<th align='center'>"+line[:-1]+"</th>\n")
	status.write("</th></tr>\n")
	status.write("</tr>")
	count=0

	for temp in junclist:
			
			rowtemp=""
			temprow=temp.split(",")
			temp1=temp.split(",")[0]
			try:
				jname=temp1.replace("/"+ciffshare+"/","")
			except:
				temp1=unicode(temp1,"utf8")
				ciffshare=ciffshare.encode("utf8")
				jname=temp1.replace("/"+ciffshare+"/","")
				jname=jname.encode("utf8")
				
			volume=temp1.split("/")[1]
			tpath=temprow[2]
			tsrv=temprow[1]
			group=temprow[3]
			status.write("<td style='font-weight:bold;'>"+jname+"</td>")
			status.write("<td style='text-align:left'>"+"//"+tsrv+tpath+"/</td>")
			status.write("<td style='text-align:left'>"+group+"</td>")
			errortest=""
			
			for line in srvlist:
	
				line=line.replace("\n","")
				
					
				if jname.decode("utf8") in server_dir[line+"/"+ciffshare]:
		
				#if exists<>True:
					
					status.write("<td style='text-align:center;color:green;'>OK</td>")
				else:
					status.write("<td style='text-align:center;background-color:red;color:white;'>MISSING</td>")
			status.write("</tr>")	
	status.write("</table>\n")
	status.write("</div>\n")
	status.write("<br>")
	status.write("<h2>NUMBER OF JUNCTIONS\t"+str(len(junclist))+"</h2>")
	status.write("<h2>DFS ROOT SERVERS OK\t"+str(len(srvlist))+"</h2>")
	status.write("</body>")	
	
	status.close()
	
	
	end_time=time.time()
	timetaken=end_time-start_time
	#print timetaken
	return uname
	

	
def checkalive(srvlist):
	"""Check List of servers to see if they are alive"""
	
	for line in srvlist:
		status=os.system("ping -c 1 "+line.replace("\n","")+null)
		if status<>0:
			print "DEAD DFS root server :"+line.replace("\n","")
			
			exclude.append(line.replace("\n","")+"\n")
		else:
			print "Found DFS root server:"+line.replace("\n","")
			
	if len(srvlist)==len(exclude):
		logstatus(270)
		shutdown(270)
		
				
	return


def smtpsend(you,mess):
	""" Send Status Emails """
	me="junc@bskyb.com"
	
	# Create message container - the correct MIME type is multipart/alternative.
	msg = MIMEMultipart('alternative')
	msg['Subject'] = "STATUS MESSAGE FROM DFS JUNCTION MANAGEMENT"
	msg['From'] = me
	msg['To'] = you

	# Create the body of the message (a plain-text and an HTML version).
	text = "Junction replication status \n"
	html = mess

	# Record the MIME types of both parts - text/plain and text/html.
	part1 = MIMEText(text, 'plain')
	part2 = MIMEText(html, 'html')

	msg.attach(part1)
	msg.attach(part2)
	# Attach parts into message container.
	# According to RFC 2046, the last part of a multipart message, in this case
	# the HTML message, is best and preferred.	
	msg.attach(part1)
	msg.attach(part2)

	# Send the message via local SMTP server.
	s = smtplib.SMTP('localhost')
	# sendmail function takes 3 arguments: sender's address, recipient's address
	# and message to send - here it is sent as one string.
	s.sendmail(me, you, msg.as_string())
	s.quit()
	return
	
	
	
	

def check(jdetails,jfile,server):
	"""check existance against a junction file"""
	tempjunc=jdetails.replace("\\","\\\\")
	temp=filter(lambda x: tempjunc in x, jfile)
	if len(temp)==0:
		logstatus(79,"//"+server+"/"+jdetails.split(",")[0][1:],masterconf)
		return 0
	else:
		logstatus(80,"//"+server+"/"+jdetails.split(",")[0][1:],masterconf)
		return -1
			

def ndap(ldap):
    """Creates an edir path from ldap"""
    ldap=ldap.replace(",ou=",".")
    ldap=ldap.replace(",o=",".")
    ndap=ldap.replace("cn=","")
    return ndap
    
    



def ldappath(path):
	""" Split and create an ldap path for object named with CN"""
	parts=path.split(".")
	i=len(parts)
	i=i-1
	newpath=""
	first="cn="+parts[0]+","
	last="o="+parts[i]
	for c in range(1,i):
		newpath=newpath+"ou="+parts[c]+","
	finalpath=first+newpath+last
	return(finalpath)


def bulkdel(slist,srv):
	"""Bulk Delete of a single Junction from Multiple Servers"""
	
	
	count1=1
	for temp in slist:
		temp=temp.replace("\n","")
		temp=temp.replace("\r","")
		items=temp.split(",")
		count=len(items)
		#print items
		if count>=1:
			
			jpath=items[0]
			volumename=jpath.split("/")[1]
			#print jpath,volumename
			juncsource=cifsnov(line[:-1],volumename)
			#juncsource=cifsnov(srv,volumename)
			tvol1=ndap(juncsource["clustervol"][0])
			mp=findmp(juncsource["clustervol"][0])
			#print jpath
			jpath=mp+"/"+jpath.split("/")[-1]
			
			pathtemp=userhome+"/"+srv+"-"+volumename
			lfiles=os.listdir(pathtemp)
			#print lfiles
			#print jpath
			p=jpath.split("/")[-1]
			
			if p not in lfiles:
				logstatus(62,jpath)
				shutdown(62)
			else:
				print "Junction Name validated"
			#sys.exit()
			temp=deljunc1(jpath,srv)
			
			
		else:
			print "Error in Line "+str(count1)
			shutdown(91)
		count1=count1+1
		

def volumes(tpath):
	"""Split Volume path up for destination"""
	tpath=tpath.replace("/media/nss","")
	#print tpath
	tpath1=tpath.split("/")
	volume=tpath1[1]
	path=tpath.replace("/"+tpath1[1],"")
	return volume,path
	

def listdir(d):
	temp=filter(lambda x: os.path.isdir(os.path.join(d, x)), os.listdir(d))
	return(temp)
	

	

def pwset(srvname):
	"""Used to Set Credentials for the rest of the client"""
	aduser=config.get("ad_config","user")
	ediruser=config.get("edir_config", "user")
	linuser=config.get("linux_user","user")
	pw=raw_input("Enter Password for Edir User "+ediruser+"\t\t\t:")
	pw1=raw_input("Enter Password for AD User "+aduser+"\t:")
	edirpw=lib.encrypt_val(pw)
	adpw=lib.encrypt_val(pw1)
	
	config.set("ad_config","pw",adpw)
	config.set("edir_config","pw",edirpw)
	pw=raw_input("Enter Password for linux User "+linuser+" \t\t\t:")
	linpw=lib.encrypt_val(pw)
	#print linpw
	config.set("linux_user","pw",linpw)
	pw=raw_input("Enter Password for AD Service Account "+adaccount+" \t\t\t:")
	adpw1=lib.encrypt_val(pw)
	config.set("ad_config","adaccountpw",adpw1)
	
	with open(jconf, 'wb') as configfile:
    		config.write(configfile)
	print "\nPasswords set"
	return

def pw(srvname,user,pw1):
	"""Extracts encrypted passwords"""
	if pw1==None:
		#print srvname
		pw1=config.get(user,"pw")

		pw=lib.decrypt_val(pw1)
		#print pw
		if pw==None:
			print "Username ? :"+user
			#user=raw_input("Username ? :")
			pw=getpass.getpass("Password ? :")
			if len(user)==0 or len(pw)==0:
				logstatus(30)
				
				shutdown(30)
		
		
	return (user,pw)

def scpget(server,user,password,sourcedir,destdir):
	"""scp initialisation"""
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(server, username=user, password=password)
	scp = SCPClient(ssh.get_transport())
	start_time=time.time()
	
	#try:
	scp.get(sourcedir,destdir,recursive=True,preserve_times=True)
	
	end_time=time.time()
	timetaken=end_time-start_time
	print "Time Taken to copy file (seconds):"+str(timetaken)[:-10]
	print
	
	return

    

def remotecmd(cmd,address,user,pw):
	"""Executes remote command on server via ssh"""
	error=""
	if debug=="yes":
		print "Checking for Server .."+address
		print cmd,address,user,pw
	ping(address)
	
	
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(address, username=user,password=pw)
		stdin, stdout, stderr = ssh.exec_command(cmd)
		#output=stdout
		output=stdout.readlines()
		error=stderr.readlines()
		#print error,output
		
	except:
		print sys.exc_info()
		output="Connection Error"
	
	return(output,error)
	


	
def nssfunc(command,auth,buff=3000):
	"""Helper Routine for writing NSS VFS File"""
	auth.write("<virtualIO><datastream name=\"command\"/></virtualIO>")
	#print command.encode("utf-8")
	try:
		auth.write(command)
	except:
		command=command.encode("utf-8")
		auth.write(command)
	auth.seek(0,0)
	temp1=auth.read(buff)
	if debug=="yes":
		print "XML Command is :"
		print "================"
		print command
		print "XML Response is :"
		print "================"
		print temp1 
	return(temp1)
	


def deljunc(jpath,srv):
	"""Function to remove a named DFS Junction"""
	
	print "Junction Path is \t:"+jpath
	vol=jpath.split("/")[1]
	#print vol
	jpath1=jpath.replace("/"+vol,vol.upper()+":").replace("/","\\")
	#print jpath1
	file = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/manage.cmd", os.O_CREAT | os.O_RDWR)
	file.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")

	cmdstring="""<nssRequest>
   <dfs>
      <deleteLink>
         <pathName>"""+jpath1+"""</pathName>
      </deleteLink>
   </dfs>
</nssRequest>"""
	cmdpath="/Manage_NSS/manage.cmd"
	#cmdpath="/_admin/Manage_NSS/manage.cmd"
	res=nssfunc(cmdstring,file)
	result=xmltodict.parse(res)
	temp=result["nssReply"]["dfs"]["deleteLink"]["result"]
	uncpath="//"+srv+jpath
	if temp["@value"]=="0" and temp['description']=="success":
		res=0
		print
		logstatus(56,uncpath)
		
		
		
	else:
		res=-1
		logstatus(55,uncpath)
			
	
	return(res)
	
	
	
def createjunc(jpath,tvol,tpath,group,srv):
	"""Revised junction create code just using cifs and no mount points"""
	
	if op=="sadd" or op=="srvadd":
		print 
		print "Junction Path (NSS) \t:"+jpath
		print "Target Volume (EDIR) \t:"+tvol
		print "Target Path   (NSS) \t:"+tpath
		print 
	jvol=jpath.split("/")[1]
	folder=jpath.replace("/"+jvol,"")
	file1 = ctx.open ("smb://"+srv+"/_admin/Manage_NSS/manage.cmd", os.O_CREAT | os.O_RDWR)
	file1.write("<virtualIO><datastream name=\"command\"/></virtualIO>\n")
	
	try:
		cmdstring=u"""<nssRequest>
			<dfs>
				<createLink>
					<pathName><![CDATA["""+jpath+"""]]></pathName>
						<junction>          
							<ndsVolume>
								<ndsObject><![CDATA["""+tvol+"""]]></ndsObject>
							</ndsVolume>
							<path><![CDATA["""+tpath+"""]]></path>
						</junction>
				</createLink>
			</dfs>
		</nssRequest>\n"""
	except:
		tpath=unicode(tpath,"utf-8")
		cmdstring=u"""<nssRequest>
			<dfs>
				<createLink>
					<pathName><![CDATA["""+jpath+"""]]></pathName>
						<junction>          
							<ndsVolume>
								<ndsObject><![CDATA["""+tvol+"""]]></ndsObject>
							</ndsVolume>
							<path><![CDATA["""+tpath+"""]]></path>
						</junction>
				</createLink>
			</dfs>
		</nssRequest>\n"""

	#Process VFS Command
	temp=nssfunc(cmdstring,file1)
	
	result=xmltodict.parse(temp)
	temp=result["nssReply"]["dfs"]["createLink"]["result"]
	if temp["@value"]=="0" and temp['description']=="success":
		res=0
		if op=="sadd" or op=="srvadd":
			logstatus(54,"//"+srv+jpath.replace("/media/nss",""),rights_junc.upper())
		
		
	else:
		res=-1
		if op=="sadd":
			logstatus(53,jpath)
		if temp["@value"]=="-1":
			logstatus (80,"//"+srv+jpath,masterconf)
		
	print
	
	return (res)

	
		

def findhost(ldapsrv,dn,user,pw):
	"""based on the DN of the volume in LDAP Find the Host Server"""
	
	temp=ldapfind(ldapsrv,"Volume",dn,["hostServer","hostResourceName"],user,pw)
	
	srv=temp[0][1]["hostServer"][0]
	vol=temp[0][1]["hostResourceName"][0]
	temp=ldapfind(ldapsrv,"ncpServer",srv,["nfapCIFSServerName"],user,pw)
	srvname=temp[0][1]["nfapCIFSServerName"][0]
	return(srvname,vol)


		
	
	
def readnit(srv,user,pw):
	"""Read nit config from named server"""
	out,err=remotecmd("nitconfig get",srv,user,pw)
	return out,err


def grpcheck(grplist,grpname):
	"""Check group list against internal table calculated at Runtime"""
	temp=grpname.split("\\")
	
	grpname=temp[1]
	dname=temp[0]
	if dname<>domain.split(".")[0]:
		#print "Domain Invalid"
		return(-1)
	target=filter(lambda x: grpname.lower() == x.lower(), grplist)
	
	if len(target)<>0:
		#print "Group "+grpname+" found in AD"
		return(0)
	else:
		#print "not found"
		return(-1)	
		
def renamefile(ctx,old,new):
	state=ctx.rename(old,new)

	return

def cifs_copy_back(cpath,ctx,duri):
	"""cifs copy file from local disk to remote"""
	sfile = open(cpath, 'r')
	dfile = ctx.open(duri, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
	ret = dfile.write(sfile.read())
	if ret < 0:
		raise IOError("smbc write error")
	sfile.close()
	dfile.close()
	return True
	
def cifs_copy(ctx, suri, dpath):
	"""cifs copy file from remote to local disk"""
	sfile = ctx.open(suri, os.O_RDONLY)
	dfile = open(dpath, 'wb')
	dfile.write(sfile.read())
	dfile.flush()
	sfile.close()
	dfile.close()
	return True
	
#================================================================================================================
# Main Code Loop
# Function added to fix problem with pyinstaller
#================================================================================================================


# Unicode setup
UTF8Writer = getwriter('utf8')
sys.stdout = UTF8Writer(sys.stdout)

attrib=["cn","objectClass"]

patch_crypto_be_discovery()
progname=os.path.basename(sys.argv[0])


null="> /dev/null 2>&1"
debug="no"
pid=os.getpid()

#user=os.getlogin()
user=os.environ['USER']

version="2.17(Beta)"	
config = configparser.ConfigParser(inline_comment_prefixes=("#"))

confpath="/var/opt/novell/junction"

	
#Setup Logging	
loglevel="DEBUG"
logdir="/var/opt/novell/junction"
pid1=str(pid)

logstat="STATUS ("+user+":"+pid1+") "

logger= logging.getLogger("Junction")


fh=logging.FileHandler(logdir+"/"+progname.replace(".py","")+".log")
formatter=logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt='%d/%m/%Y %H:%M:%S')
fh.setFormatter(formatter)
logger.addHandler(fh)
fh1=logging.handlers.SysLogHandler(address='/dev/log')
fh1.setFormatter(formatter)

logger.addHandler(fh1)


loglevelset="logger.setLevel(logging."+loglevel.upper()+")"
exec loglevelset


# Read config file

try:
	jconf=confpath+"/junction.conf"
	config.read(jconf)
 
except:
    print "No junction.conf file .. exiting"
    logstatus(32,jconf)
    shutdown(32)
    

	

 
try:
	ediruser=config.get("edir_config","user")
	linuser=config.get("linux_user","user")
	context=config.get("edir_config","context")
	rights_junc=config.get("edir_config","rights_junc")
	rights_dest=config.get("edir_config","rights_dest")
	ldapsrv=config.get("edir_config","LdapSrv")
	domain=config.get("ad_config","Domain")
	dn=config.get("edir_config","BaseContext")
	adminuser=config.get("edir_config","Admin")
	masterconf=config.get("junction","MasterConf")
	validate=config.get("junction","ValidateReport_html")
	validatecsv=config.get("junction","ValidateReport_csv")
	srvimport=config.get("junction","SrvList")
	savepath=config.get("junction","SavePath")
	logdir=config.get("junction","LogDir")
	destRequired=config.get("junction","destRequired")
	aduser=config.get("ad_config","User")
	base=config.get("edir_config","BaseContext")
	srvbasecontext=config.get("edir_config","SrvBaseContext")
	linuser=config.get("linux_user","User")
	ldaptimeout=config.get("edir_config","LdapTimeout")
	adsearchbase=config.get("ad_config","AdSearchBase")
	juncvol=config.get("edir_config","CifsShare")
	rogroups=config.get("edir_config","CheckRoGroup")
	rogroupsuffix=config.get("edir_config","RoGroup_Suffix")
	ciffshare=config.get("edir_config","cifsshare")
	rights_junc=config.get("edir_config","rights_junc")
	rights_ro=config.get("edir_config","rights_dest_ro")
	pageSize=int(config.get("ad_config","pageSize"))
	listreport_html=config.get("junction","listreport_html")
	volumereport_html=config.get("junction","volumereport_html")
	dfsAlias=config.get("junction","dfsalias")
	adKeytabName=config.get("ad_config","adkeytabname")
	adaccount=config.get("ad_config","adaccount")
	adaccountpw=config.get("ad_config","adaccountpw")
except:
	exc_type, exc_obj, exc_tb = sys.exc_info()
	print sys.exc
	print exc_tb.tb_lineno
	logstatus(42,jconf)
	shutdown(42)
	
	




	
basedn=srvbasecontext

#==============================================================
#read objects from edir
#==============================================================


logger.info(logstat+"Program Started")
logger.info(logstat+"Parameters passed to Python are "+str(sys.argv))

print 
print  progname.lower().replace(".py","")+" version: "+version
print 
print "Written by Micro Focus Solution Consulting - 2017"
print 
print "Using config file "+jconf
print

desc="""%prog is a program to allow for the creation and synchronisation of a defined list of junctions to a group of servers held in servers.lst."""



parser = OptionParser(description=desc,add_help_option=False)

parser.add_option("-j","--jpath",help="Location of Junction UNC Path without Server Name : /vol1/junction",dest="jpath",action="callback",callback=vararg_callback)
parser.add_option("-t","--tvol",help="Target Cluster resource name")
parser.add_option("-v","--ver",action="store_true",dest="version1")
parser.add_option("-p","--path",help="Target Volume Path full path from the root of the NSS Volume",dest="path",action="callback",callback=vararg_callback)
parser.add_option("-o","--op",help="")
parser.add_option("-g","--group",help="Group to Add Rights to Junction (AD Style DOMAIN\\GROUP",dest="group",action="callback",callback=vararg_callback)
parser.add_option("-i","--imp",help="File made up of junction location,target volume,path, and rights to assign to junction")
parser.add_option("-c","--conf",help="Custom list of servers in the form xx.conf")
parser.add_option("-r","--rights",help="Rights to be added to junction destination")
parser.add_option("-a","--adel",help="Auto Remove Extra Directories in Volume Root (yes/no) Default = no")
parser.add_option("-u","--upd",help="Overide and add missing junctions (yes/no) Default = No")
parser.add_option("-d","--debug",help="Turn Debug yes or no (yes/no). Default is no")
parser.add_option("-n","--node",help="Node Name of server to add to server list")
parser.add_option("-q","--quota",help="Directory quota to be added to junction target [GB]")
parser.add_option("-h","--help",action="store_true",dest="help1")
parser.add_option("-l","--verbose",help="Turn on verbose mode (no by default yes/no)")
parser.add_option("-f","--filetype",help="File type of report")
#parser.add_option("-v","--volume",help="Volume")

(options, args) = parser.parse_args()
required=[]

#==================================
# Processing Command Line Options
#==================================

if options.verbose=="yes":
	verbose="yes"
else:
	verbose="no"

if options.help1:
	required=["help1"]
	displayhelp()
	shutdown()
	
if options.version1:
	print "\n"
	print "Junction Version is "+version
	print "\n"
	shutdown()


if options.debug:
	debug="yes"
else:
	debug="no"


if options.upd==None or options.upd.lower()=="no":
	upd="n"
elif options.upd.lower()=="yes":
	upd="y"
elif "=" in options.upd.lower():
	logstatus(94)
	shutdown(94)
else:
	upd="n"
	
		
if options.op=="statuscodes":
	required=["op"]
if options.op=="srvadd":
	required=["op","node"]
if options.op=="srvdel":
	required=["op","node"]
if options.op=="validate":
	required=["op"]
if options.op=="add":
	required=["jpath","tvol","path","op","rights","group","node"]
if options.op=="del":
	required=["jpath","op"]
if options.op=="badd":
	required=["op","imp"]
if options.op=="bdel":
	required=["op","imp"]
if options.op=="madd":
	required=["op","imp"]
if options.op=="sadd":
	required=["op","jpath","tvol","path","group"]
if options.op=="sdel":
	required=["op","jpath"]
if options.op=='report':
	required=["op","filetype"]
if options.op=='list':
	required=["op"]
if options.op=="dir":
	required=["op","path","tvol"]
if options.op=="deldir":
	required=["op","path","tvol"]
if options.op=="commands":
	required=["op"]
if options.op=="quota":
	required=["op","jpath","quota"]
if options.op=="password":
	required=["op"]
if options.op=="rights":
	required=["op","jpath"]
if options.op=="usageover":
	required=["op","quota"]
if options.op=="rebuild":
	required=["op","node"]
if options.op=="volume":
	pass
if options.op=="rename":
	required=["op","jpath"]
if options.op=="check":
	required=["op","conf"]
if options.op=="grpchange":
	required=["op","jpath","group"]
	
conf=options.conf
		
op=options.op

if op==None:
	logstatus(92)
	shutdown(92)

if debug=="yes":	
	print required
	print op

for m in required:
	if not options.__dict__[m]:
		
		if op.lower()<>"help":
			print "Mandatory option is missing\n"
			displayhelp()
			logstatus(31,"")
		
		shutdown()
		
#==================================
# Validate command line options
#==================================

jpath=options.jpath
if jpath<>None:
	jpath=" ".join(jpath)
	checkpath(jpath)



tvol=options.tvol

destsrv=tvol


tpath=options.path
if tpath<>None:
	tpath=" ".join(tpath)
	checkpath(tpath)

op=options.op


group=options.group

if group<>None:
	group=" ".join(group)
	if "\\" not in group:
		logstatus(63,group)
		shutdown (63)
	
fpath=options.imp
if options.adel==None or options.adel.lower()=="no":
	adel="n"
elif options.adel.lower()=="yes":
	adel="y"

quota=options.quota
if quota<>None:
	if quota.isdigit():
		quota=str(quota)+"GB"
	else:
		logstatus(68,quota)
		shutdown(68)
		
		


pwtemp=pw("dfs","edir_config",None)

pwtemp1=pw("dfs","ad_config",None)

nocach=["commands","help","report","passwd","list","rebuild","statuscodes","rights","sadd","sdel","ver","connections","check","password","cluster","keytab"]

if op not in nocach and op in commands:
	
	volcache=volist(ldapsrv,adminuser,pwtemp[1],basedn)
	srvlist1=vserver(basedn,adminuser,pwtemp[1])
	adgrplist=ldapsearch(domain,aduser,pwtemp1[1],adsearchbase,"group",attrib,pageSize)

else:
	if op=="rename":
		srvlist1=vserver(basedn,adminuser,pwtemp[1])
		adgrplist=singlesearch(domain,aduser,pwtemp1[1],adsearchbase,"group",group.split("\\")[1],attrib)
	if op=="destvolume":
		srvlist1=vserver(basedn,adminuser,pwtemp[1])	
	if op=="dir":
		srvlist1=vserver(basedn,adminuser,pwtemp[1])
	if op=="rebuild":
		srvlist1=vserver(basedn,adminuser,pwtemp[1])
	if op=="rights" or op=="sdel" or op=="dir" or op=="grpchange":
		srvlist1=vserver(basedn,adminuser,pwtemp[1])
		volcache=volist(ldapsrv,adminuser,pwtemp[1],basedn)
	if op=="sadd":
		srvlist1=vserver(basedn,adminuser,pwtemp[1])
		volcache=volist(ldapsrv,adminuser,pwtemp[1],basedn)
		adgrplist=singlesearch(domain,aduser,pwtemp1[1],adsearchbase,"group",group.split("\\")[1],attrib)

	
#================================================================================
# Error checking for contents of the -o option	
#================================================================================
		
	if op not in commands:
		logstatus(166,op)
		shutdown(166)	



#======================================================================================================
# Destination Volume Usage Report
#======================================================================================================		

if op=="destvolume":
	output=[]
	footer=[]
	formats=["html","csv","text"]
	logstatus(280)
	if options.filetype<>None:
		filetype=options.filetype
		if filetype not in formats:
			filtetype="text"
	else:
		filetype="text"
	if volumereport_html==None and filetype=="html":
		logstatus(282,masterconf)
		shutdown(282)
		
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	share="_admin"
	username=ediruser
	password=pw1[1]
	
	
	
	
	ctx=smbc.Context(auth_fn=auth_fn)
	vollist=OrderedDict()
	for line in junclist:
		linetemp=line.split(",")
		junction=unicode(linetemp[0],"utf8")
		target_srv=linetemp[1]
		target_path=linetemp[2]

		target_unc="//"+target_srv+"/"+target_path.split("/")[1]
		if target_unc in vollist.keys():
			vollist[target_unc].append(junction)
		else:
			vollist[target_unc]=[]
			vollist[target_unc].append(junction)

	
	formatting="{:<40}{:<40}{:<40}"
	
	if filetype=="text":
		print
		print formatting.format("VOLUME","JUNCTIONS","FREE%")
		print
	if filetype=="html":
		status=codecs.open(volumereport_html,"w","utf-8")
		htmlheader("Destination Volume Usage",["VOLUME","JUNCTIONS","FREE%"])	
	for line in vollist:
		volume=line.split("/")[-1]
		server=line.split("/")[2]
		destserver=cifsnov(server,volume,srvlist1)
		novvol=destserver["clustervol"][0].split(",")
		volume1=novvol[0].split("_")[1]
		numjunc=len(vollist[line])
		free=volused(ctx,server,volume1)
	
		if filetype=="text":
			print formatting.format(line,"[ "+str(numjunc).rjust(4)+" ]","[ "+free+" ]")
		if filetype=="html":
			output.append([line,str(numjunc),free])
				
		
	if filetype=="html":
		
		htmlbody(output,footer)
		logstatus(260,volumereport_html)	
	print
	logstatus(281)
	shutdown()			
		

#=========================================================================
# Cluster Status Information
#=========================================================================

if op=="cluster":
	print
	exclude=[]
	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
		except:
			logstatus(46,srvimport)
			shutdown(46)
	
	
	checkalive(srvlist)
	# If servers are down then cut them from scope
	if len(exclude)<>0:
			srvlist=[item for item in srvlist if item not in exclude]
	print
	logstatus(130)
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	server=srvlist[0].replace("\n","")
	username=linuser
	password=pw2[1]
	share="_admin"
	
	
	# Evaluate Clusters in Tree from MGM Groups
	clusterlist=clusterlookup(ldapsrv,pw1[1])
	if len(clusterlist)==0:
		logstatus(132,ldapsrv)
		shutdown(132)
	
	if debug=="yes":
		for key,line in clusterlist.iteritems():
			print key,line
		
		
	
	
	
	print
	print "STATUS OF DFSROOT CLUSTER RESOURCES IN "+srvimport
	print
	
	for clustername,line in clusterlist.iteritems():
		server=line[0]+"."+domain
		#server=srvlist[0]
		res,nodes=cluster(server,user,password)
		
	
		cname=clustername
		print "CLUSTER NAME\t\t:"+cname
		print 
		print "Nodes in Cluster:"
		print 
		for line in nodes[cname]["node"]:
			print "\t"+line
		print
	
	
	
	
		for line in srvlist:
			line=line.replace("\n","")
			srvname=line.replace(domain,"").upper().replace("-","_").replace(".","")
			res1=filter(lambda x: x["name"]==srvname, res)
		
	
			for line in res1:
			
				time=int(line["upSince"].split("=")[-1])
				time=datetime.datetime.fromtimestamp(time).strftime('%H:%M:%S %d-%m-%Y')
				print "CLUSTER RESOURCE NAME\t:"+line["name"]
				print "State\t\t\t:"+line["state"]
				try:
					print "Location\t\t:"+line["location"]
				except:
					print "Location\t\t:"+"Not assigned"
				print "Up Since\t\t:"+time
				print
	
	
	
	logstatus(131)
	shutdown()


#===========================================================================
#   Add of single junction to defined location
#===========================================================================
if op=="add":
	logger.info(logstat+ "Add of junction to a single server")
	node=options.node
	group=options.group
	rights=options.rights
	
	

	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	server=node
	username=ediruser
	password=pw1[1]
	share="_admin"
	
	ctx=smbc.Context(auth_fn=auth_fn)
	stat=cifsjunc(server,jpath,tvol,tpath,username,password,rights,group[0])
	
	
	#print st
	
	if stat=="0":
		logger.info("STATUS Junction "+jpath+" exists on "+server)
		print "STATUS Junction "+jpath+" exists on "+server
		shutdown(0)
	else:
		logstatus(59,jpath,rights_junc.upper())
		shutdown(59)
	
	
	
	


#============================================================================
# Change the service account passwords
#============================================================================


if options.op=="password":
	print "This will change the password of the service accounts used by Junction.\n"
	pwset("dfs")
	print "Username and Password Set for edir and linux user\n"
	
	logger.info(logstat+"New Password Set for AD,Edir and Linux Users")
	
	shutdown()


#============================================================================
# Show meanings of status codes
#============================================================================

if op=="statuscodes":
	try:
		code=int(sys.argv[-1])
		print str(code)+" "+errorlist[code]
		print 
	except:
		exit_codes(errorlist)
	logger.info(logstat+"Display of status codes")
	shutdown()
	
	
#============================================================================
# Checks Rights on Existing Junction
#============================================================================
	
if op=="rights":
	
	logger.info(logstat+"Running Rights command against "+jpath)
	rows,cols=checkscreen()
	
	exclude=[]
	print
	print "Check the assigned rights for both the source and the target "
	stat,junclist1=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	volume=jpath.split("/")[1]
	if debug=="yes":
		print jpath
		print volume
	
	
	items=checklist(junclist1,jpath)
	
	if len(items)<>3:
		print
		logstatus(65,jpath,masterconf)
		shutdown(65)
		

	
	server=items[0]
	path=items[1]
	group=items[2]
	if debug=="yes":
		print "Destination Server\t:"+server
		print "Destination Path\t:"+path
		print "Destination Group\t:"+group
	
		
	volumename=path.split("/")[1]
	destserver=cifsnov(server,volumename,srvlist1)
	novvol=destserver["clustervol"][0].split(",")
	volume1=novvol[0].split("_")[1]
	mp=findmp(destserver["clustervol"][0],volcache)
	ncpvol=mp.split("/")[-1]
	
	print "="*cols
	print "Junction Rights for junction "+jpath
	print "="*cols
	
	username=ediruser
	password=pw1[1]
	share="_admin"
	
	
	volume=path.split("/")[1]
	path2=path.split("/")[2]
	try:
		path1=ncpvol+":\\"+path2
	except:
		
		path2=unicode(path2,"utf8")
		path1=ncpvol+":\\"+path2
	
	fldinfo=folderinfo(path1,server)
	if fldinfo[1]=="9223372036854775807":
		quota="Not Set"
		inuse="0"
		free="0"
	else:
		quota=size(int(fldinfo[1]))
		inuse=size(int(fldinfo[2]))
		if fldinfo[2]<>"0":
			quota1=int(fldinfo[1])
			inuse1=int(fldinfo[2])
			free1=(quota1/inuse1)
			free=100/free1
			free=str(free)+"%"
		else:
			free="0%"
	
	
	formatting="{:>5}"
	
	
	
	
	if fldinfo[-1]=="success":
		print "Target Server\t:"+server
		print "Target Path\t:"+path+"\n"
		print
		print "Target Quota\t:"+formatting.format(quota)
		print "Quota Used\t:"+formatting.format(inuse)
		print "Used\t\t:"+formatting.format(free)+"%"
		print
		print "\tTrustees"
		print "\t--------"
		for line in fldinfo[0]:
			print "\t"+line[0]+"\t["+line[1]+"]"
		print
		

	
	print "="*cols
	print "Servers that hold the junction "+jpath
	print "="*cols
	#print 

	for line in srvlist:
		print "-"*cols
		print "Junction Rights for "+line[:-1]
		print "-"*cols
		volumename=jpath.split("/")[1]
		destserver=cifsnov(line[:-1],volumename,srvlist1)
		novvol=destserver["clustervol"][0].split(",")
		volume1=novvol[0].split("_")[1]
		path2=jpath.split("/")[-1]
		mp=findmp(destserver["clustervol"][0],volcache)
		
		try:
			path1=volume1+":\\"+path2
		except:
			path2=unicode(path2,"utf8")
			path1=volume1+":\\"+path2
		
		fldinfo=folderinfo(path1,line.replace("\n",""))
	
		if fldinfo[-1]=="success":
			print "Junction Path\t:"+jpath
			print
			print "\tTrustees"
			print "\t--------"
			for line in fldinfo[0]:
				print "\t"+line[0]+"\t["+line[1]+"]"
			print
		
		
		
		
		
		
			
	print "_"*cols
	shutdown()
	
#============================================================================
# Command Examples
#============================================================================


if op=="commands" or op=="help":
	logger.info("STATUS ("+user+":"+pid1+") Command help")
	displayhelp()
	shutdown()
	

#============================================================================
# List Files in remote NSS Folder
#============================================================================


if op=="dir":
	try:
		volumename=tpath.split("/")[1]
	except:
		logstatus(40,volumename)
		shutdown(40)
	
	destserver=cifsnov(tvol,volumename,srvlist1)
	novvol=destserver["clustervol"][0].split(",")
	volume1=novvol[0].split("_")[1]	
	fullpath="/media/nss/"+volume1.upper()+tpath.replace("/"+volumename,"")
	cmd="ls "+fullpath+" -all"
	pw=pw("dfs","linux_user",None)
	results=remotecmd(cmd,tvol,linuser,pw[1])
	print "Directory is '"+tvol+":"+tpath+"'"
	print
	for line in results[0]:
		line=line.replace("\m","")
		line=line.replace("\n","")
		print line
	shutdown()
	
	
#============================================================================
# Add Server to server.lst
#============================================================================

if op=="srvadd":
	server=options.node
	
	
	
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	
	if not os.path.isfile(adKeytabName):
		logstatus(223,adKeytabName)
		shutdown(223)
		
		
	
	logstatus(170,server)
	
	print 
	if server+"\n" in srvlist:
			logstatus(177,server,srvimport)
			shutdown(177)
	
	print "Checking IP Address of "+server+"\n"
	temp=dnscheck(server)
	if temp[0]=="-1":
		logstatus(172,server)
		shutdown(172)
	
	
	temp1=dnscheck(dfsAlias)

	if temp[0] not in temp1:
		logstatus(173,server,temp[0],dfsAlias)
		shutdown(173)
	
	
	if conf<>None:
		print "STATUS Using Custom Server List "+conf
		srvlist=open(conf,'r').readlines()
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
			
		except:
			print "Server List Not found"
			logstatus(46,srvimport)
			shutdown(46)
			
	server=options.node
	
	if server+"\n" in srvlist:
		logstatus(45,server)
		shutdown(45)
	else:
		stat=ping(server)
		if stat<>0:
			logstatus(47,server)
			shutdown(47)
			
		else:
			pw=pw("dfs","edir_config",None)
			username=ediruser
			password=pw[1]
			share=ciffshare
			print """Server is about to be configured. This process will make several changes to the server if required."""
			print 
			while True:
				cnt=raw_input("Server "+server+" Is about to be configured, do you want continue (y/n)?")
				print
				if cnt=="y" or cnt=="y":
					break					
				else:
					logstatus(101)
					shutdown(101)
					
			print
			
			ctx=smbc.Context(auth_fn=auth_fn)
			# Read cifs and nit config from server
			temp=cifsconfig(server,linuser,password)
			
			
			# Make any required changes
			cifsset(server,username,password,temp)
			
			dirname="smb://"+server+"/"+ciffshare
		
			try:
				ls=ctx.opendir(dirname).getdents()
				logstatus(174,ciffshare,server)
				print
			except:
				logstatus(175,ciffshare,server)
				print
				logstatus(176,ciffshare,server)
				print
				servername=server.split("/")[0]
				temp=listvol(server,ediruser,password)
				while True:
					print
					path=raw_input("Enter NCP Volume Name for server "+server+" to create the CIFS share on?")
					
					if path.upper() in temp:
				
						temp=createshare(server,ciffshare,path.upper())
						break
					else:
						print
						logstatus(221,path,server)
						print
			
			
			keytabupdate(ctx,server,dfsAlias)
		
			
			
			while True:
				print
				cnt=raw_input("Server "+server+" Is about to be provisioned with all junctions, do you want to continue (y/n)?")
				if cnt=="y" or cnt=="Y":
					break					
				else:
					logstatus(101)
					shutdown(101)
			
			
			
			juncsource=cifsnov(server,ciffshare,srvlist1)

			
			volume=ndap(juncsource["clustervol"][0])
			
			count=len(junclist)
			junctotal=0
			for temp in junclist:
				mp=findmp(juncsource["clustervol"][0],volcache)
				jprop=temp.split(",")
				jpath=jprop[0]
				tpath=jprop[2]
				group=jprop[3]
				print
				print "Creating Junction "+jpath+" on "+server
				print 
				
			
				destserver=cifsnov(jprop[1],jprop[2].split("/")[1],srvlist1)
				targetedir=destserver["clustervol"][0]
				targetedir=ndap(targetedir)
				temp=tpath.split("/")
				tpath1="/"+temp[-1]	
				fld=jpath.split("/")[-1]
				try:
					mp=mp+"/"+fld
				except:
					fld=unicode(fld,"utf8")
					mp=mp+"/"+fld
				
				
				temp=createjunc(mp,targetedir,tpath1,jprop[3],server)
				fld=""
				
				mp=mp.replace("/media/nss","")
				volume=mp.split("/")[1].upper()
				mp=mp.replace("/"+volume,"")
				path=volume+":\\"+mp.replace("/","")		
				group=group[:-1]
				stat=addrights(server,path,rights_junc,group)
				if stat=="9001":
					logstatus(162,group)
				if stat=="0":
					
					print 
					print "STATUS Rights Applied to Junction\n"
					logger.info(logstat+" Junction "+jpath+" Created and Rights applied on server "+server)
					junctotal+=1
				
			
			
			
			print 
			print "Summary"
			print 	
			numjunc=len(junclist)
			actual=junctotal
			print "Number of Junctions in Master.lst\t\t:"+str(numjunc)
			print "Number of Junctions on "+server+"\t:"+str(actual)
			print "Missing Junctions on "+server+"\t:"+str(numjunc-actual)
			print
			writefile(srvimport.replace(".lst",".lock"),srvimport,server+"\n")
			logstatus(224,server,srvimport)
			if numjunc-actual<>0:
				
				logstatus(102,server)
				shutdown(102)
			
			logstatus(171,server)
			
			
	shutdown()

#============================================================================
# Remove a server from the list of servers to be processed
#============================================================================
	
if op=="srvdel":
	server=options.node
	rows,cols=checkscreen()
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
	logstatus(logstat+"Remove server "+server+" from "+srvimport)
	print "*="*cols
	print "Deleting "+server+" from the list of servers"
	print "="*cols
	
	
	if server+"\n" in srvlist and len(srvlist)>1:
		srvlist1=open(srvimport+"1","w")
		for line in srvlist:
			if line==server+"\n":
				print "Line removed"
			else:
				srvlist1.write(line)
		srvlist1.close()
		
		cmd="cp "+srvimport+"1 "+srvimport
		#print cmd
		os.system(cmd)
		os.system("rm "+srvimport+"1")

		shutdown()
	else:
		logstatus(48,(server,srvimport))
		shutdown(48)
		
	
#============================================================================
# List junctions on all servers
#============================================================================


if op=="list":
	reptype=options.filetype
	if reptype=="None":
		reptype=="text"
		
	logger.info("STATUS ("+user+":"+pid1+") Running List of Junctions")
	summary={}
	exclude=[]
	missing={}
	footer=[]
	trim=20
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	
		
	
	stat,junclist1=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	
	if len(junclist1)==0:
		logstatus(34,masterconf)
		shutdown(34)
	count=0
	
	print 

	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
		
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
			checkalive(srvlist)
			# If servers are down then cut them from scope
			if len(exclude)<>0:
				srvlist=[item for item in srvlist if item not in exclude]
		except:
			logstatus(32,masterconf)
			shutdown(32)
	# Establish longest junction		
	longest=max(junclist1,key=len)
	
	big=longest.split(",")
	server=srvlist[0].replace("\n","")
	username=ediruser
	password=pw1[1]
	share="_admin"
	ctx=smbc.Context(auth_fn=auth_fn)
	
	formatting="{:<"+str(len(big[0])+25)+"}{:<"+str(len(big[1])+len(big[2])+25)+"}{:<"+str(len(big[3])+10)+"}"
	
	linecount=0
	count=0
	output=[]
	print
	for temp in srvlist:
		temp=temp.replace("\n","")
		if reptype<>"html":
			
			print
		
		
		loc="/"+ciffshare
		
		
		path=temp+loc
		listfiles=dir1(ctx,path)
		
		errors=0
		dirs=[]
		
		for temp1 in listfiles:
			if "._" in temp1 or "Icon" in temp1 or ".." in temp1 or "." in temp1 or "vldb" in temp1:
				continue
			temp2=loc+"/"+temp1
			target=filter(lambda x: "/"+ciffshare+"/"+temp1 == unicode(x.split(",")[0],"utf8"), junclist1)
			if len(target)==2:
				pass
				#print target
				#sys.exit()
			if len(target)>0:
				target=target[0].split(",")
				
				if target[3][:-1]=="NONE":
					target[3]="\n"
				if reptype=="html":
					try:
						output.append(["//"+temp+loc+"/"+temp1,"//"+target[1]+target[2]+"/",target[3][:-1]])
					except:
						
						target[1]=unicode(target[1],"utf8")
						try:
							target[2]=unicode(target[2],"utf8")
						except:
							target[2]=target[2].encode("utf8")
						target[3]=unicode(target[3],"utf8")
						
						#print temp,temp1,target[1],target[2],target[3]
						#output.append([temp.replace("."+domain,"")+":"+loc+"/"+temp1,target[1].replace("."+domain,"")+":"+target[2]+"/",target[3][:-1]])
						output.append(["//"+temp+loc+"/"+temp1,"//"+target[1]+target[2]+"/",target[3][:-1]])
				else:
					try:
						#print formatting.format(temp.replace("."+domain,"")+":"+loc+"/"+temp1,"-->"+target[1].replace("."+domain,"")+":"+target[2],target[3][:-1])
						print formatting.format("//"+temp+loc+"/"+temp1,"-->"+"//"+target[1]+target[2]+"/",target[3][:-1])
					except:
						#tempu=unicode(temp,"utf8")a
						tempu=temp.encode("utf8")
						
						domainu=domain.encode("utf8")
						locu=unicode(loc)
						
						#loc=loc.encode("utf8")
						target[1]=unicode(target[1],"utf8")
						target[2]=unicode(target[2],"utf8")
						target[3]=unicode(target[3],"utf8")
						#formatting=formatting.encode("utf8")
						#temp=temp.replace("."+domain,"")
						#target[1]=target[1].replace("."+domain,"")
						sourcesrv="//"+tempu+locu+"/"+temp1
						sourcesrv=sourcesrv.encode("utf8")
						
						destsrv="-->"+"//"+target[1]+target[2]+"/"
						destsrv=destsrv.encode("utf8")
					
						print formatting.format(sourcesrv,destsrv,target[3][:-1])
						
					
			count=count+1
			
			if len(target)==0:
				
				dirs.append("/"+ciffshare+"/"+temp1)
				
			else:
				errors=errors+1
		print
		missing[temp]=dirs
		summary[temp]=str(count)
		count=0
		
		
		
		if reptype=="html":
			
			status=codecs.open(listreport_html,"w","utf-8")
			
			htmlheader("List Report",["JUNCTION PATH","JUNCTION TARGET","AD GROUP"])
			
		
		
	#print missing
	#print 
	print "SUMMARY"
	print
	if reptype=="html":
		footer.append("SUMMARY")
	formatting="{:<20}{:>8}"
	for line in srvlist:
		line=line.replace("\n","")
		if reptype<>"html":
			#line1=line.replace("."+domain,"")
			line1=line
		else:
			line1=line
		try:
			print formatting.format(line,summary[line1])
		except:
			
			line=line.encode("utf8")
			print formatting.format(line,summary[line1])
			
		
		if reptype=="html":
			footer.append([line+":"+summary[line]])
			
	print
	if reptype=="html":
		htmlbody(output,footer)
		logstatus(260,listreport_html)
	flag=0
	for line in summary:
		if len(junclist1)<>int(summary[line]):
			logstatus(252,line,summary[line],masterconf,str(len(junclist1)))
			flag=1
	if flag==1:
		shutdown(252)
	shutdown()
	
	
#=====================================================		
# Add Single Junction, multiple servers.
#======================================================

if op=="sadd":
	
	if rogroups.lower()=="yes":
		rogroup=group+rogroupsuffix
	print
	print "Add Single junctions to Multiple Servers Selected\n"
	logger.info(logstat+"Add Single Junction to Multiple Servers for junction "+jpath)
	
	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
		except:
			logstatus(46,srvimport)
			shutdown(46)
	
	

	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	server=srvlist[0].replace("\n","")
	username=ediruser
	password=pw1[1]
	share="_admin"
	
	ctx=smbc.Context(auth_fn=auth_fn)
	
	exclude=[]
	print "Edir User\t:"+adminuser
	print "Linux User\t:"+linuser
	print "AD User\t\t:"+aduser
	basedn=domain.replace(".",",dc=")
	basedn="dc="+basedn
	# Check for group in ad.
	result=checkgroup(adgrplist,group)
	# if group not found in ad then do not continue
	
	
    
    #Check to see if servers answer ping
	checkalive(srvlist)
	print
	# If servers are down then cut them from scope
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	
	volumename=tpath.split("/")[1]
	volume=jpath.split("/")[1]
	
	if os.path.exists(masterconf):
		stat,jread=readfile(masterconf.replace(".lst",".lock"),masterconf)
	else:
		logstatus(36,masterconf)
		cmd="touch "+masterconf
		os.system(cmd)
		stat,jread=readfile(masterconf.replace(".lst",".lock"),masterconf)
		
	
	junclist=[jpath+","+tvol+","+tpath+","+group]

	
	volume1,path=volumes(tpath)
	
	volumename=tpath.split("/")[1]
	try:
		targetfolder="//"+tvol+"/"+volume1+"/"+path.replace("/","")+"/"
	except:
		tvol=unicode(tvol,"utf8")
		path=unicode(path,"utf8")
		
		volume1=unicode(volume1,"utf8")
		#targetfolder=tvol.replace("."+domain,"")+":"+volume1+"/"+path.replace("/","")
		targetfolder="//"+tvol+"/"+volume1+"/"+path.replace("/","")+"/"
		
	stat=folder(ctx,"smb://"+tvol+"/"+volume1,path.replace("/",""))
	
	if stat==-1:
		logstatus(52,targetfolder)
		shutdown(52)
	else:

		logstatus(57,targetfolder,rights_dest.upper())
		print
		
	
	destserver=cifsnov(tvol,volumename,srvlist1)

	novvol=destserver["clustervol"][0].split(",")
	volume1=novvol[0].split("_")[1]

	
	try:
		fullpath="/media/nss/"+volume1.upper()+path
	except:
		path=unicode(path,"utf8")
		fullpath="/media/nss/"+volume1.upper()+path
	# Assign Rights to Target for Junction
	
	path=path.replace("/",":\\")
	path=volume1.upper()+path
	
	
	stat=addrights(tvol,path,rights_dest,group)
	if rogroups.lower()=="yes":
		rights="rf"
		stat=addrights(tvol,path,"rf",rogroup)
		if stat<>"0":
			if stat=="-9001":
				logstatus(60,rogroup)
			
		#print path
	temp=setfileinfo(tvol,volume,path)
	
	
	if quota<>None:
		temp=setquota(path,quota,tvol)
		if temp<>"0":
			logstatus(66,(quota,path))
		
		
	
	targetedir=destserver["clustervol"][0]
	targetedir=ndap(targetedir)
	
	errcount=0
	
	for line in srvlist:
		
		
		line=line.replace("\n","")
		if line in exclude:
			print "\n"
			print "Server "+line.replace("\n","")+" Not responding to Pings so not processed"
			print "\n"
			continue
		path1="/"+line
		if upd<>"y":
			stat=check(junclist[0],jread,line)
			if stat==-1:
				errcount=1
		else:
			print "Update enabled so forcing entry to be added"
			stat=0
		
		

		
		if stat==0:
			
		
			
			volumename=jpath.split("/")[1]
			
			juncsource=cifsnov(line,volumename,srvlist1)
		
			mp=findmp(juncsource["clustervol"][0],volcache)
			volume=ndap(juncsource["clustervol"][0])
			
			
			temp=tpath.split("/")
			tpath1="/"+temp[-1]
			fld=jpath.split("/")[-1]
			try:
				mp=mp+"/"+fld
			except:
				#mp=unicode(mp,"utf-8")
				fld=unicode(fld,"utf-8")
				mp=mp+u"/"+fld
			
			# Call Create Junction
			
			stat=createjunc(mp,targetedir,tpath1,group,line)
			
			if stat==0:
				
				stat1={jpath:"yes"}
				
				mp=mp.replace("/media/nss","")
				volume=mp.split("/")[1].upper()
				mp=mp.replace("/"+volume,"")
				path=volume+":\\"+mp.replace("/","")
			
				#temp=setfileinfo(line.replace("\n",""),volume,path)
				
				
				stat=addrights(line,path,rights_junc,group)
				
				if stat<>"0":
					pass
					print "Rights to Junction not correct"
				if rogroups.lower()=="yes":
					rights="rf"
					stat=addrights(tvol,path,"rf",rogroup)
					if stat<>"0":
						if stat=="-9001":
							logstatus(60,rogroup)
							#print "RO Group Not assigned"
				
			else:
				pass
			
			
                    
		else:
			pass
		
		
		jc=junclist[0].replace("\\","\\\\")+"\n"
        if jc not in jread:
            writefile(masterconf.replace(".lst",".lock"),masterconf,jc)
        
	if errcount<>0:
		shutdown(80)
	else:
		shutdown()
	
#==============================================================
#	Delete Single Junction from Multiple servers
#==============================================================

if op=="sdel":
	
	logger.info(logstat+"Delete Single Junction "+jpath)
	
	
	
	exclude=[]

	print "Remove Single Junction "+jpath
	print 
	#print
	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
			#print srvlist
		except:
			print "Server List Not found"
			logger.info("Server List not found")
			shutdown(46,srvimport)	
	stat,junclist1=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	password=pw1[1]
	
	# Setup Authentication to CIFS
	ctx=smbc.Context(auth_fn=auth_fn)
		
	
	print "Edir User\t:"+adminuser
	print "Linux User\t:"+linuser
	print 
	
	username=ediruser
	
	checkalive(srvlist)
	
	print
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	
	
	volume=jpath.split("/")[1]
	
	items=checklist(junclist1,jpath)
	
	if len(items)<>3:
		logstatus(65,jpath,masterconf)
		shutdown(65)
		
	if len(items)==3:
		server=items[0]
		path=items[1]
		group=items[2].replace("\n","")
		if debug=="yes":
			print "Destination Server\t:"+server
			print "Destination Path\t:"+path
			print "Destination Group\t:"+group
	
		volumename=path.split("/")[1]
		destserver=cifsnov(server,volumename,srvlist1)
		novvol=destserver["clustervol"][0].split(",")
		volume1=novvol[0].split("_")[1]
		
		mp=findmp(destserver["clustervol"][0],volcache)
		try:
			path=mp+"/"+path.split("/")[-1]
		except:
			path=path.decode("utf-8")
			mp=mp.decode("utf-8")
			path=mp+"/"+path.split("/")[-1]
			
		path1=volume1+":\\"+path.split("/")[-1]
		temp=delrights(server,path1,group)
		uncpath="//"+server+path.replace("/media/nss","")
		if temp=="0":
			logstatus(104,group,uncpath)
		if temp=="20856":
			#print "[STATUS] Trustee "+group+" not found"
			logstatus(103,group)
			
		
		
		
		
	for line in srvlist:
		
               
		print 
		print "Server:\t"+line.replace("\n","")
		print
		if line.replace("\n","") in exclude:
			print "Server "+line.replace("\n","")+" Not found by Ping so Processing Excluded"
			print "\n"
			continue
		jname=jpath.split("/")[-1]
		path=line.replace("\n","")+jpath.replace("/"+jname,"")+"/"
		ls=dir1(ctx,path)
		try:
			jname1=jname.decode("utf-8")
		except:
			janme1=jname
		if jname1 in ls:
			#print "found"
			
			volumename=jpath.split("/")[1]
			
			juncsource=cifsnov(line.replace("\n",""),volumename,srvlist1)
		
			mp=findmp(juncsource["clustervol"][0],volcache)
			volume=ndap(juncsource["clustervol"][0])
			volume=mp.split("/")[-1]
			vol1=jpath.split("/")[1]
			try:
				jpath1=jpath.replace(vol1,volume)
			except:
				jpath=jpath.decode("utf-8")
				jpath1=jpath.replace(vol1,volume)
				
			stat=deljunc(jpath1,line.replace("\n",""))
		
	
	
	lock=filelock.FileLock(masterconf.replace(".lst",".lock"))
	try:
		lock.acquire(timeout=time)
	except filelock.Timeout:
		stat=-1
	try:
		cmd="sed -i.bak '/.*"+jpath.replace("/",".")+",.*/Id' "+masterconf
		os.system(cmd)
	except:
		#masterconf=masterconf.decode("utf-8")
		try:
			jpath=unicode(jpath,"utf-8")
		except:
			pass
		#jpath=jpath.decode("utf-8")
		cmd=u"sed -i.bak '/.*"+jpath.replace("/",".")+u",.*/Id' "+masterconf
		args = shlex.split(cmd)
		subprocess.check_call(args)
		#cmd=cmd.decode("utf-8")
		
	#os.system(cmd)
	
	shutdown()
#=============================
# report routine
#=============================		


if op=="report":
	server_dir={}
	defaultdirs=[u"._DUPLICATE_FILES",u"DO_NOT_DELETE.txt",u"._Icon\xef\x80\x8d",u"._\xef\x80\xa9",u"._.DS_Store",u"Icon\xef\x80\x8d",u"._.VolumeIcon.icns",u".VolumeIcon.icns",u".DS_Store",u"._NETWARE",u"vldb",".trash-0",u"~DFSINFO.8-P",u".",u"..",u"~DFSJUNCTIONINFO",u".Trash-0",]
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	
	exclude=[]	
	stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
	checkalive(srvlist)
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	
	server=srvlist[0].replace("\n","")
	username=ediruser
	password=pw1[1]
	share="_admin"
	ctx=smbc.Context(auth_fn=auth_fn)
	
	for line in srvlist:
		path=line.replace("\n","")+"/"+juncvol
		ls=dir1(ctx,path)
		ls=list(set(ls) - set(defaultdirs))
		server_dir[path]=ls
	
	
	
	filetype=options.filetype
	if filetype.lower()=="csv":
		name=createcsv(srvlist)
	elif filetype.lower()=="html":
		
		name=createtable(srvlist,ctx,server_dir,ciffshare)
		print
	else:
		logstatus(261,filetype)
		shutdown(261)
		
	logstatus(260,name)
	shutdown()

#=============================
# validate routine
#=============================


if op=="validate":
	server_dir={}
	
	errors=0
	success=0
	
	stat,junclist1=readfile(masterconf.replace(".lst",".lock"),masterconf)
	exclude=[]
	rightscheck={}
	
	
	
	if conf<>None:
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
		
	else:
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
		except:
			logstatus(srvimport)
			shutdown(46)
	print
	print "Checking to see if DFSROOT Servers are active..."
	print
	checkalive(srvlist)
	print

	#==============================
	# Retrieve Secure Passwords
	#==============================
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	print "Edir User\t:"+adminuser
	print "Linux User\t:"+linuser
	print "AD User\t\t:"+aduser
	if debug=="yes":
		print pw3
		print "-------"
	print
	logstatus(250)
	print
	
	basedn=domain.replace(".",",dc=")
	basedn="dc="+basedn
	
	try:
		stat,junclist=readfile(masterconf.replace(".lst",".conf"),masterconf)
		
	except:
		logstatus(35,masterconf)
		shutdown(35)
	
	if len(junclist)==0:
		logstatus(34)
		shutdown(34)
	else:
	
		volume=junclist[0].split(",")[0]
		volume=volume.split("/")[1]
		
		
	jpathtemp=jpath
	
	
	if jpath<>None:
		try:	
			if juncvol not in jpath:
				print "Not a DFS Junction "
				logstatus(10)
				shutdown(10)
		except:
			jpath=unicode(jpath,"utf8")
			if juncvol not in jpath:
				print "Not a DFS Junction "
				logstatus(10)
				shutdown(10)
			
		try:
			junclist = [x for x in junclist if jpath in x]
		except:
			junclist = [unicode(item,"utf8") for item in junclist]
			junclist = [x for x in junclist if jpath in x]
		
		if len(junclist)==0:
			logstatus(65,jpath,masterconf)
			shutdown(10)
		
	
	# derive list of junctions
	junctions=[]
	
	
	#CIFS Init
	server=srvlist[0].replace("\n","")
	username=ediruser
	password=pw1[1]
	share="_admin"
	ctx=smbc.Context(auth_fn=auth_fn)
	
	
	for line in junclist:
		junc=line.split(",")[0]
		jname=junc.split("/")[-1]
		try:
			junctions.append(unicode(jname))
		except:
			junctions.append(unicode(jname,"utf8"))
		#junctions.append(jname)
	mp={}	
	#volcache={}
	
	total=""
	
	
		
	#Build Dictionary of Files in each Server folder location
	
	#server_dir holds a directory listings of all servers holding junctions.
	# filter list of default directories in the filesystem
	defaultdirs=["._DUPLICATE_FILES","DO_NOT_DELETE.txt",u"._Icon\xef\x80\x8d",u"._\xef\x80\xa9","._.DS_Store",u"Icon\xef\x80\x8d","._.VolumeIcon.icns",".VolumeIcon.icns",".DS_Store","._NETWARE","vldb",".trash-0","~DFSINFO.8-P",".","..","~DFSJUNCTIONINFO",".Trash-0","VOL1.txt","VOL2.txt","VOL3.txt"]
	
	
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	
	if debug=="yes":
		print srvlist
		
	
	#build list of junctions
	
	for line in srvlist:
		path=line.replace("\n","")+"/"+juncvol
		ls=dir1(ctx,path)
		ls=list(set(ls) - set(defaultdirs))
		server_dir[path]=ls
	
	
	
	err=[]
	wrong=0
	valstart=time.time()
	
	
	
	
	for line in junclist:
		errtemp=errors
		r1=r2=g1=g2=1
		
		juncopt=line.split(",")
		jpath=juncopt[0]
		server=juncopt[1]
		tvol=juncopt[1]
		destfolder=juncopt[2]
		volumename=destfolder.split("/")[1]
		group=juncopt[3][:-1]
		
		# Check derived destination folder
		destserver=cifsnov(server,volumename,srvlist1)
		novvol=destserver["clustervol"][0].split(",")
		volume=novvol[0].split("_")[1]+":\\"
		mp=findmp(destserver["clustervol"][0],volcache)
		volumename=mp.split("/")[-1]
		try:
			parts=[volumename,":",destfolder.replace("/"+volumename.lower(),"").replace("/","\\")]
		except:
			destfolder=unicode(destfolder,"utf8")
			parts=[volumename,":",destfolder.replace("/"+volumename.lower(),"").replace("/","\\")]
			#print parts
		path="".join(parts)
		path1=destfolder.replace("/"+volumename.lower(),"")
		
		#Checking Rights for Junction Target
		#If Group is none do not check
		
		if "\\" not in group:
			logstatus(207,"//"+server+destfolder)
			r1=0
			g1=0			
		else:
			r1,g1=rights(server,volume,path1,rights_dest,group)
		ptemp="//"+server+"/"+volume.replace(":\\","/")[:-1]+path1.replace("//","/")
		#print ptemp
		if g1<>0:
			#print r1,g1
			errors+=1
			#trustee missing
			logstatus(200,group,ptemp)
			
		if r1<>0 and g1==0:
			# rights wrong
			logstatus(201,group,ptemp)
			errors+=1
		
		if rogroups.lower()=="yes":
			r2,g2=rights(server,volume,path1,"rf",group+rogroupsuffix)
			
			if g2<>0:
				logstatus(200,group+rogroupsuffix.upper(),ptemp)
				errors+=1
			if r2<>0 and g2==0:
				logstatus(201,grouo,ptemp)
				errors+=1
		if r1==0 and g1==0:
			if verbose=="yes":
				print "\n"
				print "="*cols
				print "Junction:\t"+jpath
				print "="*cols
				print
				print "Target   :\t"+destfolder
				print "Server   :\t"+server
				print "Group    :\t"+group+"\t["+rights_dest.upper()+"]"
				if rogroups=="yes":
					print "ROGroup   :\t"+group+rogroupsuffix+"\t["+rights_ro.upper()+"]"
				srv=line.split(",")[1]
				print
				
		
		if upd=="n":
			if r1==0 and g1==0:
				success+=1
					
			else:
				pass
		
		else:
			# if update is yes and errors detected"
			if g1==1 or r1==1:
				print "error detected"
				
				destserver=cifsnov(tvol,volumename,srvlist1)
				novvol=destserver["clustervol"][0].split(",")
				volume1=novvol[0].split("_")[1]
				
				stat1=addrights(server,path,rights_dest,group)
				
				if stat1=="21215":
					logstatus(206,path.split(":")[0].upper())
					shutdown(206)
				if stat1=="-9001":
					logstatus(200,group,ptemp)
					errors+=1
				if stat1=="0":
					logstatus(202,group,ptemp)
					success+=1			
				
				if rogroups=="yes":
					
					stat2=addrights(server,path,"rf",group+rogroupsuffix)
					if stat2=="-9001":
						logstatus(200,group+rogroupsuffix,ptemp)
						errors+=1
					if stat2=="0":
						logstatus(202,group+rogroupsuffix,ptemp)
						success+=1			
				if stat1=="0":
						logstatus(202,group,ptemp)
						success+=1
								
			
							
				else:
					if stat1=="20407":
						logstatus(52,ptemp)
						errors=+1
						volume2=destfolder.split("/")[1]
						path1=destfolder.split("/")[-1]
						
						stat=folder(ctx,"smb://"+tvol+"/"+volume2,path1.replace("/",""))
			
						if stat==0:
							errors-=1
							success-=1
							logstatus(203,ptemp)
							stat=addrights(server,path,rights_dest,group)
							success+=1
							logstatus(204,group,ptemp,rights_dest.upper())
							
							if rogroups=="yes":
								stat=addrights(server,path,"rg",group+rogroupsuffix)
								logstatus(204,group+rogroupsuffix.upper(),ptemp,rights_dest.upper())
						else:
							path2="/"+path1
							
							stat=folder(ctx,"smb://"+tvol+"/"+volume2,path1.replace("/",""))
							stat1=addrights(server,path,rights_dest,group)
							#print stat,stat1
							if stat and stat1:
								logstatus(53,ptemp)
							else:
								logstatus(52,ptemp)
					
		dirtemp=jpath.split("/")[-1]
		dirpath=jpath.replace("/"+dirtemp,"")
		
						
		for line in srvlist:
			
			line=line.replace("\n","")
			if verbose=="yes":
				print 
				print " SERVER Being Processed is "+line[:-1]
				print 
				
				
			srvpath=line+dirpath
			dirlist=server_dir[srvpath]
			
			jname=jpath.split("/")[-1]
			
			try:
				grpname=group.split("\\\\")[1]
			except:
				grpname=group
			#print grpname
			
			#ptemp=line.replace("\n","")+":"+jpath
			ptemp="//"+line+jpath
			try:
				jname=unicode(jname,"utf8")
			except:
				pass
			#temp=[x for x in dirlist if jname == x]
			if jname in dirlist:
				#print "Junction Found"
				volumename=jpath.split("/")[1]
				if "\\\\" in group:
					r1,g1=checkfldr(jpath,line.replace("\n",""),jpath.split("/")[1],group,linuser,pw2[1],srvlist1)
				else:
					logstatus(207,ptemp)
					errors+=1
					r1=0
					g1=0
				
				
				if r1==0 and g1==0:
					success+=1
					if verbose=="yes":
						
						print "Junction :\t"+jpath
						print "Server   :\t"+line.replace("\n","")
						print "Group    :\t"+group+"\t["+rights_junc.upper()+"]"
						if rogroups=="yes":
							print "ROGroup  :\t"+group+rogroupsuffix+"\t["+rights_ro.upper()+"]"
						print
					
				else:
					if g1<>0:
						logstatus(200,group,ptemp)
						errors+=1
						if upd=="y":
							
							volname=jpath.split("/")[1]
							
							destserver=cifsnov(line.replace("\n",""),volname,srvlist1)
							novvol=destserver["clustervol"][0].split(",")
							volume1=novvol[0].split("_")[1]
							
							path2=path1.split("/")[1]
							path3=volume1+":\\"+path2.replace("/","\\")
							if debug=="yes":
								print "-------"
								print "[DEBUG] "+volume1,novvol[0]
								print "[DEBUG] "+path3
								print "-----"
							
							stat=addrights(line.replace("\n",""),path3,rights_junc,group)
						
							
							if stat=="0":
								logstatus(202,group,ptemp)
								success+=1
								errors-=1
							
					if r1<>0 and g1==0:
						logstatus(201,group,ptemp)
						
						errors+=1
				
				if rogroups.lower()=="yes":
					r2,g2=checkfldr(jpath,line.replace("\n",""),jpath.split("/")[1],group+rogroupsuffix,linuser,pw2[1],srvlist1)
					
		
					if g2<>0:
							logstatus(200,group+rogroupsuffix,ptemp)
							errors+=1
					if r2<>0 and g2==0:
							logtatus(201,group+rogroupsuffix,ptemp)
							errors+=1
					if r2==0 and g2==0:
						success+=1
				#print jname in dirlist	
			else:
				# Junction Missing
				logstatus(82,ptemp)
				errors+=1
				
				if upd=="n":
					pass
		
				else:
					volumename=jpath.split("/")[1]
			
					juncsource=cifsnov(line.replace("\n",""),volumename,srvlist1)
		
					mp=findmp(juncsource["clustervol"][0],volcache)
					volume=ndap(juncsource["clustervol"][0])
		
			
					temp=destfolder.split("/")
					tpath1="/"+temp[-1]
					fld=jpath.split("/")[-1]
					mp=mp+"/"+fld
					
			
					# Call Create Junction
					res=createjunc(mp,volume,tpath1,group,line.replace("\n",""))
					if debug=="yes":
						print line.replace("\n","")
						print tpath1
						print rights_junc
						print volume
					temppath=volume.split(".")[0]
					temppath=temppath.split("_")[1]
					temppath=temppath+":\\"+tpath1.replace("/","")
					stat=addrights(line.replace("\n",""),temppath,rights_junc,group)
					
					
					
					#res=createjunc(jpath,volume,destfolder,group,line.replace("\n",""))
					if res<>0:
						logstatus(53,ptemp)

						errors+=1
						
					else:
						logstatus(205,ptemp)
						
						success+=1
					path=line.replace("\n","")+"/"+juncvol
					ls=dir1(ctx,path)
					ls=list(set(ls) - set(defaultdirs))
					server_dir[path]=ls
		if errtemp<>errors:
			errtemp=errors
			print
		
	
	print
	stop=time.time()
	duration=stop-valstart
	if jpathtemp==None:

		print
		print "The Following Servers have extra files/folders/junctions"
		print "Each item listed is extra over the Junctions listed in "+masterconf
		print
		for line1 in srvlist:
			line1=line1.replace("\n","")
			
			
			diff=list(set(server_dir[line1+"/"+juncvol])-(set(junctions)))
			if len(diff)<>0:
				for count,line in enumerate(diff):
					
					
					temp=line1+":/"+juncvol+"/"+line
					if "._" in temp or "Icon" in temp:
						continue
					else:
						
						print temp
						
				print
			else:
				print line1+": \n"
		print
				
			

	
	
	numsrv=len(srvlist)
	numjunc=len(junclist)
	excludetemp=str(exclude)
	
	print "SUMMARY"
	print 
	print "\tJunctions Processed\t:%5d" % numjunc
	print "\tServers Per Junction\t:%5d" % numsrv
	if len(exclude)<>0:
		print
		print "\tServers Down or not responding\t:"+excludetemp.replace("\\n","")
		errors+=1
	print
	print "\tTime Taken (Seconds)\t:%8.2f" % duration
	print
	print "\tSuccessful Checks\t:%5d" % success
	print "\tUnsuccessful Checks\t:%5d" % errors
	print 
	total=numjunc*numsrv
	sec=total/duration
	print "Junctions Checked\t:%5d" % total
	print "Junctions Per Second\t:%5d" % sec
	print
	logstatus(251)
	if errors<>0:
		shutdown(10)
	else:
		shutdown()
	
	


#=============================================================================================
# Quota of a named junction
#=============================================================================================
	
if op=="quota":
	logger.info(logstat+"Setting quota for junction "+jpath)
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	
	
	
	
	username=ediruser
	password=pw1[1]
	share="_admin"
	ctx=smbc.Context(auth_fn=auth_fn)
	
	
	logger.info(logstat+"Setting Quota on target of "+jpath)
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	pw2=pw("dfs","edir_config",None)
	
	temp=list(checklist(junclist,jpath))
	
	
	if None in temp:
		logstatus(82,jpath)
		shutdown(82)
	path=temp[1]
	server=temp[0]
	destserver=cifsnov(server,path.split("/")[1],srvlist1)
	novvol=destserver["clustervol"][0].split(",")
	volume1=novvol[0].split("_")[1]
	path=volume1+":\\"+path.split("/")[-1]
	print 
	print "Setting Quota of "+str(quota)+" for junction "+jpath
	print 
	path=server+":/"+path
	temp=setquota(path,quota,server)
	if temp=="0":
		logstatus(500,quota,path)
		shutdown()
		
	else:
		logstatus(501,path)
	
	shutdown()	

#===========================================================================================
# Usage of all junction destinations
#===========================================================================================

if op=="usageover":
	if quota==None:
		logstatus(11)
		shutdown(11)
	
	quota=quota.replace("GB","")	
	
	logger.info(logstat+"Checking for usage over "+str(quota)+"%")
	
	stat,junclist=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)
	
	
	
	username=ediruser
	password=pw1[1]
	share="_admin"
	ctx=smbc.Context(auth_fn=auth_fn)
	print
	print "Checking Junction Targets with Over "+str(quota)+"% utilisation"
	print
	quota=int(quota)
	usage(junclist)
	shutdown()
#=======================================================================================
# 		Rebuild Master.lst
#=======================================================================================

""" Recreate a new list from nothing using a DFS Root server as the source"""
if op=="rebuild":
	dupcheck={}
	errors=[]
	server=options.node
	if server==None:
		logstatus(49)
		shutdown(49)
		
	
	tempmaster=masterconf+"-new"
	logstatus(210,tempmaster,server)
	print
	defaultdirs=[u"._DUPLICATE_FILES",u"DO_NOT_DELETE.txt",u"._Icon\xef\x80\x8d",u"._\xef\x80\xa9",u"._.DS_Store",u"Icon\xef\x80\x8d",u"._.VolumeIcon.icns",u".VolumeIcon.icns",u".DS_Store",u"._NETWARE",u"vldb",".trash-0",u"~DFSINFO.8-P",u".",u"..",u"~DFSJUNCTIONINFO",u".Trash-0",]
	
	server=options.node
	if server==None:
		logstatus(49)
		shutdown(49)
	
	temp=ping(server)
	
	masterconfnew=codecs.open(tempmaster,"w","utf-8")
	
	

		
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	pw3=pw("dfs","ad_config",None)

	
	username=ediruser
	password=pw1[1]
	share="_admin"
	ctx=smbc.Context(auth_fn=auth_fn)
	
	
	
	temp=dir1(ctx,server+"/"+ciffshare)
	
	count=0
	count=runloop(temp,count,ctx)
	masterconfnew.close()
	count=str(count)
	out="\nS{:>5} line(s) written to file "+tempmaster
	print
	logstatus(212,count,tempmaster,server)
	print 
	name=open(tempmaster,"r").readlines()
	fname=tempmaster
	errors=checkjlist(name)
	
	print
	print "Number of Errors in "+tempmaster+" is "+str(errors)
	
	if errors<>"0":
		logstatus(213,tempmaster,server)
		shutdown(213)	
			
	else:
		shutdown(0)
	
#==============================================================================
# Rename of Junction
#==============================================================================
if op=="rename":
	jpath=shlex.split(jpath)
	if len(jpath)<>2:
		logstatus(61,jpath)
	source=jpath[0]
	dest=jpath[1]
	print
	logger.info(logstat+"Rename Junction from "+jpath[0]+" to "+jpath[1])
		
	exclude=[]

	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
		except:
			print "Server List Not found"
			logger.info("Server List not found")
			shutdown(46,srvimport)	
	stat,junclist1=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	password=pw1[1]
	
	# Setup Authentication to CIFS
	ctx=smbc.Context(auth_fn=auth_fn)
		
	
	print "Edir User\t:"+adminuser
	print "Linux User\t:"+linuser
	print 
	
	username=ediruser
	
	checkalive(srvlist)
	
	print
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	
	jpath=source
	volume=jpath.split("/")[1]
	
	items=checklist(junclist1,jpath)

	if len(items)<>3:
		logstatus(65,jpath,masterconf)
		shutdown(65)
		
	if len(items)==3:
		server=items[0]
		path=items[1]
		group=items[2].replace("\n","")
		if debug=="yes":
			print "Destination Server\t:"+server
			print "Destination Path\t:"+path
			print "Destination Group\t:"+group
	
		volumename=path.split("/")[1]
		destserver=cifsnov(server,volumename,srvlist1)
		novvol=destserver["clustervol"][0].split(",")
		volume1=novvol[0].split("_")[1]
		
		mp=findmp(destserver["clustervol"][0],volcache)
		try:
			path=mp+"/"+path.split("/")[-1]
		except:
			path=path.decode("utf-8")
			mp=mp.decode("utf-8")
			path=mp+"/"+path.split("/")[-1]
			
		path1=volume1+":\\"+path.split("/")[-1]
	
	server=srvlist[0].replace("\n","")
	username=ediruser
	password=pw1[1]
	share="_admin"
	
	ctx=smbc.Context(auth_fn=auth_fn)
	
	for line in srvlist:
		line=line.replace("\n","")
               
		print 
		print "Server:\t"+line
		print
		if line in exclude:
			print "Server "+line+" Not found by Ping so Processing Excluded"
			print "\n"
			continue
		jname=jpath.split("/")[-1]
		path=line+jpath.replace("/"+jname,"")+"/"
		ls=dir1(ctx,path)
		try:
			jname1=jname.decode("utf-8")
		except:
			jname1=jname
		if jname1 in ls and dest.split("/")[-1] not in ls:
			
			volumename=jpath.split("/")[1]
			
			juncsource=cifsnov(line,volumename,srvlist1)
		
			mp=findmp(juncsource["clustervol"][0],volcache)
			volume=ndap(juncsource["clustervol"][0])
			volume=mp.split("/")[-1]
			vol1=jpath.split("/")[1]
			try:
				jpath1=jpath.replace(vol1,volume)
			except:
				jpath=jpath.decode("utf-8")
				jpath1=jpath.replace(vol1,volume)
		
			

			stat=deljunc(jpath1,line)
			if stat<>0:
				logstatus(151,source,dest,line)
				shutdown(151)			
			
			targetedir=juncsource["clustervol"][0]
			targetedir=ndap(targetedir)
			
			jpath2="/"+jpath1.split("/")[-2]+"/"+dest.split("/")[-1]
			stat=createjunc(mp+"/"+dest.split("/")[-1],targetedir,path1,group,line)
			temppath=volume.split(".")[0]+"/"+jpath2.split("/")[-1]
			temppath=temppath.replace("/",":\\")
		
			stat1=addrights(line,temppath,rights_junc,group)
			
			if stat==0 and stat1=="0":
				logstatus(150,source,dest,line)
			else:
				logstatus(151,source,dest,line)
				shutdown(151)				
		else:
			logstatus(152,source,dest)
			shutdown(152)
	
	lock=filelock.FileLock(masterconf.replace(".lst",".lock"))
	try:
		lock.acquire(timeout=time)
	except filelock.Timeout:
		stat=-1
		sys.exit()
	try:
		cmd="sed -i.bak 's-"+source+"-"+dest+"-g' "+masterconf
		
		os.system(cmd)
	except:
		try:
			jpath=unicode(jpath,"utf-8")
		except:
			pass
		cmd="sed -i.bak 's-"+source+"-"+dest+"-g' "+masterconf
		args = shlex.split(cmd)
		subprocess.check_call(args)
	shutdown()
	
	
#=============================================================================
# Connections on Each DFS Root Server
#=============================================================================

if op=="connections":
	logstatus(110)
	print
	summary={}
	exclude=[]
	
	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
		except:
			print "Server List Not found"
			logger.info("Server List not found")
			shutdown(46,srvimport)
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	password=pw1[1]
	linpass=pw2[1]
	# Setup Authentication to CIFS
	ctx=smbc.Context(auth_fn=auth_fn)
		
	
	print "Edir User\t:"+adminuser
	print "Linux User\t:"+linuser
	print 
	
	username=ediruser
	
	checkalive(srvlist)
	
	cmd="novcifs -Cl"
	print
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	for line in srvlist:
		ad=0
		edir=0
		line=line.replace("\n","")
		temp,error=remotecmd(cmd,line,linuser,linpass)
		print line.upper()

		if "Permission denied" in temp[0]:
			print
			logstatus(112,line)
			print
			summary[line]=[0,0]
			continue	
		if "There are no active CIFS client connections" in temp[0]:
			print
			print temp[0].replace("\n","")
			print
			summary[line]=[0,0]
			continue
		
		
		#sys.exit()
		if len(temp)<>1:
			
			#sys.exit()
			print temp[0].replace("\n","")
			print temp[1]
			for lines in temp:
				
				if "Active Directory" in lines:
					ad+=1
					print lines.replace("\n","").replace("\m","")
				elif "eDirectory" in lines:
					edir+=1
					print lines.replace("\n","").replace("\m","")
			print
		summary[line]=[ad,edir]
	
	if len(summary)>0:
		formatting="{:<40}{:>40}{:>40}"
		print formatting.format("DFS ROOT SERVER SUMMARY","AD Clients","eDirectory Clients")		
		print
	for line in srvlist:
		line=line.replace("\n","")
		print formatting.format(line,summary[line][0],summary[line][1])
	print
	logstatus(111)
	shutdown()
	
#==================================================================================
# Creation and Management of keytab	
#==================================================================================
if op=="keytab":
	
	print
	print "Creating keytab file "+adKeytabName
	print
	
	principal="cifs/"+ciffshare+"."+domain+"@"+domain.upper()
	pw3=pw("dfs","ad_config",None)
	adpass=pw3[1]
	
	adaccountpw=lib.decrypt_val(adaccountpw)
	
	basedn=adaccount.lower()
	name=basedn.split(",")[0].replace("cn=","")
	temp=adspn(domain,basedn,name,principal,aduser,adpass)
	temp=kvnocheck(domain,basedn,name,aduser,adpass)
	temp=keytabcreate(adKeytabName,principal,domain,str(temp),adaccountpw)
	print
	logstatus(222,adKeytabName)
	shutdown()
		
	
#===============================================================================
# Check Existing named .lst file
#===============================================================================


if op=="check":
	dupcheck={}
	errors=[]
	fname=options.conf
	
	try:
		stat,name=readfile(fname.replace(".lst",".lock").replace(".lst-new",".lock"),fname)
	except:
		print "File name not found"
		sys.exit()
	logstatus(120,fname)
	print
	errors=checkjlist(name)
	if errors=="0":
		logstatus(122,fname)
		shutdown()
	else:
		logstatus(122,fname)
		shutdown(121)
		
#=====================================================================================
#  Change a group assignment to an existing junction
#=====================================================================================
if op=="grpchange":
	
	jpath=options.jpath[0]
	group=options.group[0]
	print
	logstatus(140,jpath)
	status=grpcheck(adgrplist,group)
	if status<>0:
		logstatus(64,group)
		shutdown(64)
	
		
	exclude=[]

	if conf<>None:
		print "STATUS: Using Custom Server List "+conf
		stat,srvlist=readfile(conf.replace(".lst",".lock"),conf)
	else:   
		try:
			stat,srvlist=readfile(srvimport.replace(".lst",".lock"),srvimport)
		except:
			print "Server List Not found"
			logger.info("Server List not found")
			shutdown(46,srvimport)	
	stat,junclist1=readfile(masterconf.replace(".lst",".lock"),masterconf)
	
	
	pw1=pw("dfs","edir_config",None)
	pw2=pw("dfs","linux_user",None)
	password=pw1[1]
	
	# Setup Authentication to CIFS
	ctx=smbc.Context(auth_fn=auth_fn)
		
	
	print "Edir User\t:"+adminuser
	print "Linux User\t:"+linuser
	print 
	
	username=ediruser
	
	checkalive(srvlist)
	
	print
	if len(exclude)<>0:
		srvlist=[item for item in srvlist if item not in exclude]
	
	
	items=checklist(junclist1,jpath)

	if len(items)<>3:
		logstatus(65,jpath,masterconf)
		shutdown(65)
	
	old=items[2]
	
	print items
	server=items[0]
	volumename=items[1].split("/")[1]
	print volumename
	path=items[1]
	destserver=cifsnov(server,volumename,srvlist1)
	novvol=destserver["clustervol"][0].split(",")
	volume1=novvol[0].split("_")[1]
		
	mp=findmp(destserver["clustervol"][0],volcache)
	try:
		path=mp+"/"+path.split("/")[-1]
	except:
		path=path.decode("utf-8")
		mp=mp.decode("utf-8")
		path=mp+"/"+path.split("/")[-1]
			
	path1=volume1+":\\"+path.split("/")[-1]
	print path1,server,old
	
	temp=delrights(server,path1,old)
	print temp
	stat=addrights(server,path1,rights_junc,group)
	print stat
	
	
	volumename=jpath.split("/")[1]
	print volumename
			
	for line in srvlist:
		server=line.replace("\n","")
		destserver=cifsnov(server,volumename,srvlist1)
		novvol=destserver["clustervol"][0].split(",")
		volume1=novvol[0].split("_")[1]
		
		mp=findmp(destserver["clustervol"][0],volcache)
		try:
			path=mp+"/"+path.split("/")[-1]
		except:
			path=path.decode("utf-8")
			mp=mp.decode("utf-8")
			path=mp+"/"+path.split("/")[-1]
			
		path1=volume1+":\\"+path.split("/")[-1]
		print path1,server,group
		temp=delrights(server,path1,old)
		stat=addrights(server,path1,rights_junc,group)
	
	
	
	
	
	
	

		
	
	




