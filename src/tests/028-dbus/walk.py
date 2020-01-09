#!/usr/bin/python
import dbus
import xml.etree.ElementTree
import os
import sys

bus = dbus.SessionBus()

# Check that reading a property directly produces the same value as reading it via GetAll().
def check_props(objpath, interface):
	o = bus.get_object('org.fedorahosted.certmonger', objpath)
	i = dbus.Interface(o, 'org.freedesktop.DBus.Properties')
	props = i.GetAll(interface)
	for prop in props.keys():
		value = props[prop]
		if value != i.Get(interface, prop):
			print("%s: property %s.%s mismatch (%s, %s)" % (objpath, interface, prop, value, i.Get(interface, prop)))
			return False
	return True

# Try to call the method.
def examine_method(objpath, interface, method, idata):
	in_args = 0
	out_args = 0
	o = bus.get_object('org.fedorahosted.certmonger', objpath)
	i = dbus.Interface(o, interface)
	for child in idata.getchildren():
		if child.tag == 'arg':
			if child.get('direction') != 'out':
				in_args = in_args + 1
			else:
				out_args = out_args + 1
	if in_args == 0:
		# Takes no inputs, so just call it.
		m = i.get_dbus_method(method)
		if out_args == 0:
			m()
			print("[ %s: %s.%s ]\n" % (objpath, interface, method))
		elif out_args == 1:
			result = m()
			print("[ %s: %s.%s ]\n%s\n" % (objpath, interface, method, result))
		else:
			result = m()
			print("[ %s: %s.%s ]\n%s\n" % (objpath, interface, method, result))
	elif method == 'Get' or method == 'Set' or method == 'GetAll':
		# We check on properties elsewhere.
		return True
	# Per-method exercise.
	elif method == 'add_known_ca' or method == 'remove_known_ca':
		(result, path) = i.add_known_ca('Test CA', '/usr/bin/env', [])
		if not result:
			print("[ %s : %s.%s ]: add_known_ca error\n" % (objpath, interface, method))
			return False
		result = i.remove_known_ca(path)
		if not result:
			print("[ %s : %s.%s ]: remove_known_ca error\n" % (objpath, interface, method))
			return False
		print("[ %s : %s.%s ]\nOK\n" % (objpath, interface, method))
	elif method == 'add_request' or method == 'remove_request':
		tmpdir = os.getenv('TMPDIR')
		if not tmpdir or tmpdir == '':
			tmpdir = '/tmp'
		properties = {
			'nickname': 'foo',
			'cert-storage': 'file',
			'cert-file': tmpdir + "/028-certfile",
			'key-storage': 'file',
			'key-file': tmpdir + "/028-keyfile",
			'template-email': ['root@localhost', 'toor@localhost'],
		}
		(result, path) = i.add_request(properties)
		if not result:
			print("[ %s : %s.%s ]: add_request error\n" % (objpath, interface, method))
			return False
		result = i.remove_request(path)
		if not result:
			print("[ %s : %s.%s ]: remove_request error\n" % (objpath, interface, method))
			return False
		print("[ %s : %s.%s ]\nOK\n" % (objpath, interface, method))
	elif method == 'find_ca_by_nickname':
		capath = i.find_ca_by_nickname('local')
		o = bus.get_object('org.fedorahosted.certmonger', capath)
		i = dbus.Interface(o, 'org.freedesktop.DBus.Properties')
		if i.Get('org.fedorahosted.certmonger.ca', 'nickname') != 'local':
			print("[ %s : %s.%s ] error: %s\n" % (objpath, interface, method, i.Get('org.fedorahosted.certmonger.ca', 'nickname')))
			return False
		print("[ %s : %s.%s ]\nOK\n" % (objpath, interface, method))
	elif method == 'find_request_by_nickname':
		reqpath = i.find_request_by_nickname('Buddy')
		o = bus.get_object('org.fedorahosted.certmonger', reqpath)
		i = dbus.Interface(o, 'org.freedesktop.DBus.Properties')
		if i.Get('org.fedorahosted.certmonger.request', 'nickname') != 'Buddy':
			print("[ %s : %s.%s ] error: %s\n" % (objpath, interface, method, i.Get('org.fedorahosted.certmonger.request', 'nickname')))
			return False
		print("[ %s : %s.%s ]\nOK\n" % (objpath, interface, method))
	else:
		# We're in FIXME territory.
		print method
		return False
	return True

def examine_interface(objpath, interface, idata):
	o = bus.get_object('org.fedorahosted.certmonger', objpath)
	i = dbus.Interface(o, 'org.freedesktop.DBus.Properties')
	for child in idata.getchildren():
		if child.tag == 'property':
			prop = child.get('name')
			if child.get('access') == 'read':
				# Check that we can read it.
				value = i.Get(interface, prop)
			elif child.get('access') == 'readwrite':
				if prop == 'external-helper':
					cai = dbus.Interface(o, 'org.fedorahosted.certmonger.ca')
					if cai.get_type() != 'EXTERNAL':
						print("%s: warning: property %s.%s not settable on this object" % (objpath, interface, prop))
						continue
				# Check that we can read it, tweak it, and then reset it.
				value = i.Get(interface, prop)
				i.Set(interface, prop, value)
				newvalue = None
				if child.get('type') == 'b':
					newvalue = not value
				elif child.get('type') == 'n':
					newvalue = value + 1
				elif child.get('type') == 's':
					newvalue = 'x' + value
				elif child.get('type') == 'as':
					newvalue = ['x'] + value
				else:
					print(child.get('type'))
					return False
				if newvalue:
					if newvalue == value:
						print("%s: error determining new value: (%s, %s): %s" % (objpath, interface, prop, value))
						return False
					i.Set(interface, prop, newvalue)
					if newvalue != i.Get(interface, prop):
						print("%s: property %s.%s not set: (%s, %s)" % (objpath, interface, prop, value, newvalue))
						return False
					i.Set(interface, prop, value)
					if value != i.Get(interface, prop):
						print("%s: property %s.%s not reset: (%s, %s)" % (objpath, interface, prop, newvalue, value))
						return False
		elif child.tag == 'method':
			method = child.get('name')
			if not examine_method(objpath, interface, method, child):
				return False
		elif child.tag == 'signal':
			continue
		else:
			print child.tag
			return False
	return True

def examine_object(objpath):
	o = bus.get_object('org.fedorahosted.certmonger', objpath)
	i = dbus.Interface(o, 'org.freedesktop.DBus.Introspectable')
	idata = i.Introspect()
	x = xml.etree.ElementTree.XML(idata)

	# Check if the object supports properties interfaces.
	props = False
	for child in x.getchildren():
		if child.tag == 'interface':
			if child.get('name') == 'org.freedesktop.DBus.Properties':
				props = True

	# Look at the interfaces and child nodes.
	for child in x.getchildren():
		if child.tag == 'interface':
			if props and not check_props(objpath, child.get('name')):
				return False
			if not examine_interface(objpath, child.get('name'), child):
				return False
		elif child.tag == 'node':
			if objpath == '/':
				childpath = '/' + child.get('name')
			else:
				childpath = objpath + '/' + child.get('name')
			examine_object(childpath)
		else:
			print child.tag
			return False
	return True

if not examine_object('/'):
	sys.exit(1)
sys.exit(0)
