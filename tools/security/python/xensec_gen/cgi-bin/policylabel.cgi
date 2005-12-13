#!/usr/bin/python
#
# The Initial Developer of the Original Code is International
# Business Machines Corporation. Portions created by IBM
# Corporation are Copyright (C) 2005 International Business
# Machines Corporation. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import os
import cgi
import cgitb; cgitb.enable( )
import time
import xml.dom.minidom
import xml.sax
import xml.sax.handler
from StringIO import StringIO
from sets import Set

def getSavedData( ):
	global formData, policyXml, policyLabelXml
	global formVariables, formVmNames
	global allVmChWs, allVmStes

	# Process the XML upload policy file
	if formData.has_key( 'i_policy' ):
		dataList = formData.getlist( 'i_policy' )
		if len( dataList ) > 0:
			policyXml = dataList[0].strip( )

	# The XML upload policy file must be specified at the start
	if formData.has_key( 'i_policyLabelCreate' ):
		if policyXml == '':
			msg = ''
			msg = msg + 'A Policy file was not supplied.  A Policy file '
			msg = msg + 'must be supplied in order to successfully create '
			msg = msg + 'a Policy Labeling file.'
			formatXmlError( msg )

	# Process the XML upload policy label file
	if formData.has_key( 'i_policyLabel' ):
		dataList = formData.getlist( 'i_policyLabel' )
		if len( dataList ) > 0:
			policyLabelXml = dataList[0].strip( )

	# Process all the hidden input variables (if present)
	for formVar in formVariables:
		if formVar[2] == '':
			continue

		if formData.has_key( formVar[2] ):
			dataList = formData.getlist( formVar[2] )
			if len( dataList ) > 0:
				if isinstance( formVar[1], list ):
					exec 'formVar[1] = ' + dataList[0]
				else:
					formVar[1] = dataList[0]

	# The form can contain any number of "Virtual Machines"
	#   so update the list of form variables to include
	#   each virtual machine (hidden input variable)
	for vmName in formVmNames[1]:
		newVm( vmName )

		vmFormVar = allVmChWs[vmName]
		if (vmFormVar[2] != '') and formData.has_key( vmFormVar[2] ):
			dataList = formData.getlist( vmFormVar[2] )
			if len( dataList ) > 0:
				if isinstance( vmFormVar[1], list ):
					exec 'vmFormVar[1] = ' + dataList[0]
				else:
					vmFormVar[1] = dataList[0]

		vmFormVar = allVmStes[vmName]
		if (vmFormVar[2] != '') and formData.has_key( vmFormVar[2] ):
			dataList = formData.getlist( vmFormVar[2] )
			if len( dataList ) > 0:
				if isinstance( vmFormVar[1], list ):
					exec 'vmFormVar[1] = ' + dataList[0]
				else:
					vmFormVar[1] = dataList[0]

def getCurrentTime( ):
	return time.strftime( '%Y-%m-%d %H:%M:%S', time.localtime( ) )

def getName( domNode ):
	nameNodes = domNode.getElementsByTagName( 'Name' )
	if len( nameNodes ) == 0:
		formatXmlError( '"<Name>" tag is missing' )
		return None

	name = ''
	for childNode in nameNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			name = name + childNode.data

	return name

def getDate( domNode ):
	dateNodes = domNode.getElementsByTagName( 'Date' )
	if len( dateNodes ) == 0:
		formatXmlError( '"<Date>" tag is missing' )
		return None

	date = ''
	for childNode in dateNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			date = date + childNode.data

	return date

def getDefUrl( domNode ):
	domNodes = domNode.getElementsByTagName( 'PolicyName' )
	if len( domNodes ) == 0:
		formatXmlError( '"<PolicyName>" tag is missing' )
		return None

	urlNodes = domNode.getElementsByTagName( 'Url' )
	if len( urlNodes ) == 0:
		formatXmlError( '"<Url>" tag is missing' )
		return None

	url = ''
	for childNode in urlNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			url = url + childNode.data

	return url

def getDefRef( domNode ):
	domNodes = domNode.getElementsByTagName( 'PolicyName' )
	if len( domNodes ) == 0:
		formatXmlError( '"<PolicyName>" tag is missing' )
		return None

	refNodes = domNode.getElementsByTagName( 'Reference' )
	if len( refNodes ) == 0:
		formatXmlError( '"<Reference>" tag is missing' )
		return None

	ref = ''
	for childNode in refNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			ref = ref + childNode.data

	return ref

def getSteTypes( domNode, missingIsError = 0 ):
	steNodes = domNode.getElementsByTagName( 'SimpleTypeEnforcementTypes' )
	if len( steNodes ) == 0:
		if missingIsError == 1:
			formatXmlError( '"<SimpleTypeEnforcementTypes>" tag is missing' )
			return None
		else:
			return []

	return getTypes( steNodes[0] )

def getChWTypes( domNode, missingIsError = 0 ):
	chwNodes = domNode.getElementsByTagName( 'ChineseWallTypes' )
	if len( chwNodes ) == 0:
		if missingIsError == 1:
			formatXmlError( '"<ChineseWallTypes>" tag is missing' )
			return None
		else:
			return []

	return getTypes( chwNodes[0] )

def getTypes( domNode ):
	types = []

	domNodes = domNode.getElementsByTagName( 'Type' )
	if len( domNodes ) == 0:
		formatXmlError( '"<Type>" tag is missing' )
		return None

	for domNode in domNodes:
		typeText = ''
		for childNode in domNode.childNodes:
			if childNode.nodeType == xml.dom.Node.TEXT_NODE:
				typeText = typeText + childNode.data

		if typeText == '':
			formatXmlError( 'No text associated with the "<Type>" tag' )
			return None

		types.append( typeText )

	return types

def formatXmlError( msg, xml = '', lineNum = -1, colNum = -1 ):
	global xmlMessages, xmlError

	xmlError = 1
	addMsg = cgi.escape( msg )

	if lineNum != -1:
		sio = StringIO( xml )
		for xmlLine in sio:
			lineNum = lineNum - 1
			if lineNum == 0:
				break;

		addMsg += '<BR><PRE>' + cgi.escape( xmlLine.rstrip( ) )

		if colNum != -1:
			errLine = ''
			for i in range( colNum ):
				errLine = errLine + '-'

			addMsg += '\n' + errLine + '^'

		addMsg += '</PRE>'

	xmlMessages.append( addMsg )

def formatXmlGenError( msg ):
	global xmlMessages, xmlIncomplete

	xmlIncomplete = 1
	xmlMessages.append( cgi.escape( msg ) )

def parseXml( xmlInput ):
	global xmlMessages, xmlError, xmlLine, xmlColumn

	xmlParser  = xml.sax.make_parser( )
	try:
		domDoc = xml.dom.minidom.parseString( xmlInput, xmlParser )

	except xml.sax.SAXParseException, xmlErr:
		msg = ''
		msg = msg + 'XML parsing error occurred at line '
		msg = msg + `xmlErr.getLineNumber( )`
		msg = msg + ', column '
		msg = msg + `xmlErr.getColumnNumber( )`
		msg = msg + ': reason = "'
		msg = msg + xmlErr.getMessage( )
		msg = msg + '"'
		formatXmlError( msg, xmlInput, xmlErr.getLineNumber( ), xmlErr.getColumnNumber( ) )
		return None

	except xml.sax.SAXException, xmlErr:
		msg = ''
		msg = msg + 'XML Parsing error: ' + `xmlErr`
		formatXmlError( msg, xmlInput, xmlErr.getLineNumber( ), xmlErr.getColumnNumber( ) )
		return None

	return domDoc

def parsePolicyXml( ):
	global policyXml
	global formSteTypes, formChWallTypes

	domDoc = parseXml( policyXml )
	if domDoc == None:
		return

	domRoot  = domDoc.documentElement
	domNodes = domRoot.getElementsByTagName( 'SimpleTypeEnforcement' )
	if len( domNodes ) > 0:
		steTypes = getSteTypes( domNodes[0], 1 )
		if steTypes == None:
			msg = ''
			msg = msg + 'Error processing the SimpleTypeEnforcement types.\n'
			msg = msg + 'Please validate the Policy Definition file used.'
			formatXmlError( msg )
			return

		formSteTypes[1] = steTypes

	domNodes = domRoot.getElementsByTagName( 'ChineseWall' )
	if len( domNodes ) > 0:
		chwTypes = getChWTypes( domNodes[0], 1 )
		if chwTypes == None:
			msg = ''
			msg = msg + 'Error processing the ChineseWall types.\n'
			msg = msg + 'Please validate the Policy Definition file used.'
			formatXmlError( msg )
			return

		formChWallTypes[1] = chwTypes

def parsePolicyLabelXml( ):
	global policyLabelXml

	domDoc = parseXml( policyLabelXml )
	if domDoc == None:
		return

	domRoot     = domDoc.documentElement
	domHeaders = domRoot.getElementsByTagName( 'LabelHeader' )
	if len( domHeaders ) == 0:
		msg = ''
		msg = msg + '"<LabelHeader>" tag is missing.\n'
		msg = msg + 'Please validate the Policy Labeling file used.'
		formatXmlError( msg )
		return

	pName = getName( domHeaders[0] )
	if pName == None:
		msg = ''
		msg = msg + 'Error processing the Policy Labeling header information.\n'
		msg = msg + 'Please validate the Policy Labeling file used.'
		formatXmlError( msg )
		return

	formPolicyLabelName[1] = pName

	pDate = getDate( domHeaders[0] )
	if pDate == None:
		msg = ''
		msg = msg + 'Error processing the Policy Labeling header information.\n'
		msg = msg + 'Please validate the Policy Labeling file used.'
		formatXmlError( msg )
		return

	formPolicyLabelDate[1] = pDate

	pUrl = getDefUrl( domHeaders[0] )
	if pUrl == None:
		msg = ''
		msg = msg + 'Error processing the Policy Labeling header information.\n'
		msg = msg + 'Please validate the Policy Labeling file used.'
		formatXmlError( msg )
		return

	formPolicyUrl[1] = pUrl

	pRef = getDefRef( domHeaders[0] )
	if pRef == None:
		msg = ''
		msg = msg + 'Error processing the Policy Labeling header information.\n'
		msg = msg + 'Please validate the Policy Labeling file used.'
		formatXmlError( msg )
		return

	formPolicyRef[1] = pRef

	domSubjects = domRoot.getElementsByTagName( 'SubjectLabels' )
	if len( domSubjects ) > 0:
		formVmNameDom0[1] = domSubjects[0].getAttribute( 'bootstrap' )
		domNodes = domSubjects[0].getElementsByTagName( 'VirtualMachineLabel' )
		for domNode in domNodes:
			vmName = getName( domNode )
			if vmName == None:
				msg = ''
				msg = msg + 'Error processing the VirtualMachineLabel name.\n'
				msg = msg + 'Please validate the Policy Labeling file used.'
				formatXmlError( msg )
				continue

			steTypes = getSteTypes( domNode )
			if steTypes == None:
				msg = ''
				msg = msg + 'Error processing the SimpleTypeEnforcement types.\n'
				msg = msg + 'Please validate the Policy Labeling file used.'
				formatXmlError( msg )
				return

			chwTypes = getChWTypes( domNode )
			if chwTypes == None:
				msg = ''
				msg = msg + 'Error processing the ChineseWall types.\n'
				msg = msg + 'Please validate the Policy Labeling file used.'
				formatXmlError( msg )
				return

			newVm( vmName, 1 )
			allVmStes[vmName][1] = steTypes
			allVmChWs[vmName][1] = chwTypes

def removeDups( curList ):
	newList = []
	curSet  = Set( curList )
	for x in curSet:
		newList.append( x )
	newList.sort( )

	return newList

def newVm( vmName, addToList = 0 ):
	global formVmNames
	global templateVmDel, allVmDel, templateVmDom0, allVmDom0
	global templateVmChWs, templateVmChWDel, templateVmChW, templateVmChWAdd
	global allVmChWs, allVmChWDel, allVmChWType, allVmChWAdd
	global templateVmStes, templateVmSteDel, templateVmSte, templateVmSteAdd
	global allVmStes, allVmSteDel, allVmSteType, allVmSteAdd

	# Make sure we have an actual name and check one of the 'all'
	# variables to be sure it hasn't been previously defined
	if (len( vmName ) > 0) and (not allVmDom0.has_key( vmName )):
		vmSuffix = '_' + vmName
		allVmDom0[vmName]   = modFormTemplate( templateVmDom0,   vmSuffix )
		allVmDel[vmName]    = modFormTemplate( templateVmDel,    vmSuffix )
		allVmChWs[vmName]   = modFormTemplate( templateVmChWs,   vmSuffix )
		allVmChWDel[vmName] = modFormTemplate( templateVmChWDel, vmSuffix )
		allVmChW[vmName]    = modFormTemplate( templateVmChW,    vmSuffix )
		allVmChWAdd[vmName] = modFormTemplate( templateVmChWAdd, vmSuffix )
		allVmStes[vmName]   = modFormTemplate( templateVmStes,   vmSuffix )
		allVmSteDel[vmName] = modFormTemplate( templateVmSteDel, vmSuffix )
		allVmSte[vmName]    = modFormTemplate( templateVmSte,    vmSuffix )
		allVmSteAdd[vmName] = modFormTemplate( templateVmSteAdd, vmSuffix )
		if addToList == 1:
			formVmNames[1].append( vmName )
			formVmNames[1] = removeDups( formVmNames[1] )

def updateInfo( ):
	global formData, formPolicyLabelName, formPolicyLabelDate
	global formPolicyUrl, formPolicyRef

	if formData.has_key( formPolicyLabelName[3] ):
		formPolicyLabelName[1] = formData[formPolicyLabelName[3]].value
	elif formData.has_key( formPolicyLabelUpdate[3] ):
		formPolicyLabelName[1] = ''

	if formData.has_key( formPolicyLabelDate[3] ):
		formPolicyLabelDate[1] = formData[formPolicyLabelDate[3]].value
	elif formData.has_key( formPolicyLabelUpdate[3] ):
		formPolicyLabelDate[1] = ''

	if formData.has_key( formPolicyUrl[3] ):
		formPolicyUrl[1] = formData[formPolicyUrl[3]].value
	elif formData.has_key( formPolicyLabelUpdate[3] ):
		formPolicyUrl[1] = ''

	if formData.has_key( formPolicyRef[3] ):
		formPolicyRef[1] = formData[formPolicyRef[3]].value
	elif formData.has_key( formPolicyLabelUpdate[3] ):
		formPolicyRef[1] = ''

def addVm( ):
	global formData, fromVmName, formVmNames, formVmNameDom0

	if (formData.has_key( formDefaultButton[3] )) or (formData.has_key( formVmAdd[3] )):
		if formData.has_key( formVmName[3] ):
			vmName = formData[formVmName[3]].value
			vmName = vmName.strip( )
			newVm( vmName, 1 )
			if formVmNameDom0[1] == '':
				formVmNameDom0[1] = vmName

def delVm( vmName ):
	global formVmNames, formVmNameDom0
	global allVmDel, allVmDom0
	global allVmChWs, allVmChWDel, allVmChWType, allVmChWAdd
	global allVmStes, allVmSteDel, allVmSteType, allVmSteAdd

	vmName = vmName.strip( )
	formVmNames[1].remove( vmName )
	del allVmDom0[vmName]
	del allVmDel[vmName]
	del allVmChWs[vmName]
	del allVmChWDel[vmName]
	del allVmChW[vmName]
	del allVmChWAdd[vmName]
	del allVmStes[vmName]
	del allVmSteDel[vmName]
	del allVmSte[vmName]
	del allVmSteAdd[vmName]

	if formVmNameDom0[1] == vmName:
		if len( formVmNames[1] ) > 0:
			formVmNameDom0[1] = formVmNames[1][0]
		else:
			formVmNameDom0[1] = ''

def makeVmDom0( vmName ):
	global formVmNameDom0

	vmName = vmName.strip( )
	formVmNameDom0[1] = vmName

def addVmChW( chwName ):
	global formData, allVmChW, allVmChWs

	formVar = allVmChW[chwName]
	if formData.has_key( formVar[3] ):
		chwList = formData.getlist( formVar[3] )
		formVar = allVmChWs[chwName]
		for chw in chwList:
			chw = chw.strip( )
			formVar[1].append( chw )
			formVar[1] = removeDups( formVar[1] )

def delVmChW( chwName ):
	global formData, allVmChWs

	formVar = allVmChWs[chwName]
	if formData.has_key( formVar[3] ):
		chwList = formData.getlist( formVar[3] )
		for chw in chwList:
			chw = chw.strip( )
			formVar[1].remove( chw )

def addVmSte( steName ):
	global formData, allVmSte, allVmStes

	formVar = allVmSte[steName]
	if formData.has_key( formVar[3] ):
		steList = formData.getlist( formVar[3] )
		formVar = allVmStes[steName]
		for ste in steList:
			ste = ste.strip( )
			formVar[1].append( ste )
			formVar[1] = removeDups( formVar[1] )

def delVmSte( steName ):
	global formData, allVmStes

	formVar = allVmStes[steName]
	if formData.has_key( formVar[3] ):
		steList = formData.getlist( formVar[3] )
		for ste in steList:
			ste = ste.strip( )
			formVar[1].remove( ste )

def processRequest( ):
	global formData, policyXml, policyLabelXml, formPolicyLabelUpdate
	global formVmAdd
	global formVmNames, allVmDel, allVmDom0
	global allVmChWAdd, allVmChWDel, allVmSteAdd, allVmSteDel

	if policyXml != '':
		parsePolicyXml( )

	if policyLabelXml != '':
		parsePolicyLabelXml( )

	# Allow the updating of the header information whenever
	# an action is performed
	updateInfo( )

	# Allow the adding of labels if the user has hit the
	# enter key when attempting to add a type/set
	addVm( )

	for vmName in formVmNames[1]:
		if formData.has_key( allVmDel[vmName][3] ):
			delVm( vmName )
			continue

		if formData.has_key( allVmDom0[vmName][3] ):
			makeVmDom0( vmName )

		if formData.has_key( allVmChWAdd[vmName][3] ):
			addVmChW( vmName )

		elif formData.has_key( allVmChWDel[vmName][3] ):
			delVmChW( vmName )

		elif formData.has_key( allVmSteAdd[vmName][3] ):
			addVmSte( vmName )

		elif formData.has_key( allVmSteDel[vmName][3] ):
			delVmSte( vmName )

def modFormTemplate( formTemplate, suffix ):
	formVar = [x for x in formTemplate]

	if formVar[2] != '':
		formVar[2] = formVar[2] + suffix
	if formVar[3] != '':
		formVar[3] = formVar[3] + suffix
	if (formVar[0] != 'button') and (formVar[4] != ''):
		formVar[4] = formVar[4] + suffix

	return formVar;

def makeName( name, suffix='' ):
	rName = name
	if suffix != '':
		rName = rName + '_' + suffix

	return rName

def makeNameAttr( name, suffix='' ):
	return 'name="' + makeName( name, suffix ) + '"'

def makeValue( value, suffix='' ):
	rValue = value

	if isinstance( value, list ):
		rValue = '['
		for val in value:
			rValue = rValue + '\'' + val
			if suffix != '':
				rValue = rValue + '_' + suffix
			rValue = rValue + '\','
		rValue = rValue + ']'

	else:
		if suffix != '':
			rValue = rValue + '_' + suffix

	return rValue

def makeValueAttr( value, suffix='' ):
	return 'value="' + makeValue( value, suffix ) + '"'

def sendHtmlFormVar( formVar, attrs='', rb_select=0 ):
	nameAttr  = ''
	valueAttr = ''
	htmlText  = ''

	if formVar[0] == 'text':
		if formVar[3] != '':
			nameAttr = makeNameAttr( formVar[3] )
		valueAttr = makeValueAttr( formVar[1] )

		print '<INPUT type="text"', nameAttr, valueAttr, attrs, '>'

	elif formVar[0] == 'list':
		if formVar[3] != '':
			nameAttr = makeNameAttr( formVar[3] )

		print '<SELECT', nameAttr, attrs, '>'
		for option in formVar[1]:
			print '<OPTION>' + option + '</OPTION>'
		print '</SELECT>'

	elif formVar[0] == 'button':
		if formVar[3] != '':
			nameAttr = makeNameAttr( formVar[3] )
		if formVar[4] != '':
			valueAttr = makeValueAttr( formVar[4] )

		print '<INPUT type="submit"', nameAttr, valueAttr, attrs, '>'

	elif formVar[0] == 'radiobutton':
		if formVar[3] != '':
			nameAttr  = makeNameAttr( formVar[3] )
			valueAttr = makeValueAttr( formVar[4][rb_select] )
			htmlText  = formVar[5][rb_select]
			if formVar[4][rb_select] == formVar[1]:
				checked = 'checked'
			else:
				checked = ''

			print '<INPUT type="radio"', nameAttr, valueAttr, attrs, checked, '>', htmlText

	elif formVar[0] == 'radiobutton-all':
		if formVar[3] != '':
			nameAttr = makeNameAttr( formVar[3] )
			buttonVals  = formVar[4]
			for i, buttonVal in enumerate( buttonVals ):
				htmlText = ''
				addAttrs = ''
				checked  = ''

				valueAttr = makeValueAttr( buttonVal )
				if formVar[5] != '':
					htmlText = formVar[5][i]
				if attrs != '':
					addAttrs = attrs[i]
				if buttonVal == formVar[1]:
					checked = 'checked'

				print '<INPUT type="radio"', nameAttr, valueAttr, addAttrs, checked, '>', htmlText

	if ( formVar[2] != '' ) and ( rb_select == 0 ):
		nameAttr = makeNameAttr( formVar[2] )
		valueAttr = makeValueAttr( formVar[1] )
		print '<INPUT type="hidden"', nameAttr, valueAttr, '>'

def sendHtmlHeaders( ):
	# HTML headers
	print 'Content-Type: text/html'
	print

def sendPolicyLabelHtml( ):
	global xmlError, xmlIncomplete, xmlMessages, formXmlGen
	global formVmNameDom0, formSteTypes, formChWallTypes

	print '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"'
	print '  "http://www.w3.org/TR/html4/loose.dtd">'

	print '<HTML>'

	sendHtmlHead( )

	print '<BODY>'

	# An input XML file was specified that had errors, output the
	# error information
	if xmlError == 1:
		print '<P>'
		print 'An error has been encountered while processing the input'
		print 'XML file:'
		print '<UL>'
		for msg in xmlMessages:
			print '<LI>'
			print msg
		print '</UL>'
		print '</BODY>'
		print '</HTML>'
		return

	# When attempting to generate the XML output, all required data was not
	# present, output the error information
	if xmlIncomplete == 1:
		print '<P>'
		print 'An error has been encountered while validating the data'
		print 'required for the output XML file:'
		print '<UL>'
		for msg in xmlMessages:
			print '<LI>'
			print msg
		print '</UL>'
		print '</BODY>'
		print '</HTML>'
		return

	print '<CENTER>'
	print '<FORM action="' + os.environ['SCRIPT_NAME'] + '" method="post">'
	print '<TABLE class="container">'
	print '  <COLGROUP>'
	print '    <COL width="100%">'
	print '  </COLGROUP>'

	print '  <TR>'
	print '    <TD>'
	sendHtmlFormVar( formDefaultButton, 'class="hidden"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD>'
	sendHtmlFormVar( formXmlGen )
	print '    </TD>'
	print '  </TR>'

	# Policy Labeling header
	print '  <TR>'
	print '    <TD>'
	sendPLHeaderHtml( )
	print '    </TD>'
	print '  </TR>'

	# Separator
	print '  <TR>'
	print '    <TD>'
	print '      <HR>'
	print '    </TD>'
	print '  </TR>'

	# Policy Labels (vms)
	print '  <TR>'
	print '    <TD>'
	print '      <TABLE class="full">'
	print '        <TR>'
	print '          <TD width="100%">'
	sendPLSubHtml( )
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'

	print '</TABLE>'

	# Send some data that needs to be available across sessions
	sendHtmlFormVar( formVmNameDom0 )
	sendHtmlFormVar( formSteTypes )
	sendHtmlFormVar( formChWallTypes )

	print '</FORM>'
	print '</CENTER>'

	print '</BODY>'

	print '</HTML>'

def sendHtmlHead( ):
	global headTitle

	print '<HEAD>'
	print '<STYLE type="text/css">'
	print '<!--'
	print 'BODY            {background-color: #EEEEFF;}'
	print 'TABLE.container {width:  90%; border: 1px solid black; border-collapse: seperate;}'
	print 'TABLE.full      {width: 100%; border: 0px solid black; border-collapse: collapse; border-spacing: 3px;}'
	print 'TABLE.fullbox   {width: 100%; border: 0px solid black; border-collapse: collapse; border-spacing: 3px;}'
	print 'THEAD           {font-weight: bold; font-size: larger;}'
	print 'TD              {border: 0px solid black; vertical-align: top;}'
	print 'TD.heading      {border: 0px solid black; vertical-align: top; font-weight: bold; font-size: larger;}'
	print 'TD.subheading   {border: 0px solid black; vertical-align: top; font-size: smaller;}'
	print 'TD.fullbox      {border: 1px solid black; vertical-align: top;}'
	print 'SELECT.full     {width: 100%;}'
	print 'INPUT.full      {width: 100%;}'
	print 'INPUT.link      {cursor: pointer; background-color: #EEEEFF; border: 0px; text-decoration: underline; color: blue;}'
	print 'INPUT.hidden    {visibility: hidden; width: 1px; height: 1px;}'
	print ':link           {color: blue;}'
	print ':visited        {color: red;}'
	print '-->'
	print '</STYLE>'
	print '<TITLE>', headTitle, '</TITLE>'
	print '</HEAD>'

def sendPLHeaderHtml( ):
	global formPolicyLabelName, formPolicyLabelDate
	global formPolicyUrl, formPolicyRef
	global formPolicyLabelUpdate

	# Policy Labeling header definition
	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="20%">'
	print '    <COL width="80%">'
	print '  </COLGROUP>'
	print '  <TR>'
	print '    <TD class="heading" align="center" colspan="2">Policy Labeling Information</TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Name:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyLabelName, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Date:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyLabelDate, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Policy URL:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyUrl, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Policy Reference:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyRef, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="center" colspan="2">'
	sendHtmlFormVar( formPolicyLabelUpdate )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="center" colspan="2" class="subheading">'
	print '      (The Policy Labeling Information is updated whenever an action is performed'
	print '       or it can be updated separately using the "Update" button)'
	print '    </TD>'
	print '  </TR>'
	print '</TABLE>'

def sendPLSubHtml( ):
	global formVmNames, formVmDel, formVmName, formVmAdd
	global allVmDel, allVmDom0
	global allVmChWs, allVmChWDel, allVmChW, allVmChWAdd
	global allVmStes, allVmSteDel, allVmSte, allVmSteAdd
	global formSteTypes, formChWallTypes

	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="100%">'
	print '  </COLGROUP>'

	# Virtual Machines...
	print '  <TR>'
	print '    <TD>'
	print '      <TABLE class="full">'
	print '        <COLGROUP>'
	print '          <COL width="10%">'
	print '          <COL width="40%">'
	print '          <COL width="50%">'
	print '        </COLGROUP>'
	print '        <TR>'
	print '          <TD class="heading" align="center" colspan="3">Virtual Machine Classes</TD>'
	print '        </TR>'
	print '        <TR>'
	print '          <TD colspan="2">'
	sendHtmlFormVar( formVmName, 'class="full"' )
	sendHtmlFormVar( formVmNames )
	print '          </TD>'
	print '          <TD>&nbsp;</TD>'
	print '        </TR>'
	print '        <TR>'
	print '          <TD>'
	sendHtmlFormVar( formVmAdd, 'class="full"' )
	print '          </TD>'
	print '          <TD colspan="2">'
	print '            Create a new VM class with the above name'
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'
	if len( formVmNames[1] ) > 0:
		print '  <TR>'
		print '    <TD colspan="1">'
		print '      &nbsp;'
		print '    </TD>'
		print '  </TR>'
		print '  <TR>'
		print '    <TD>'
		print '      <TABLE class="fullbox">'
		print '        <COLGROUP>'
		print '          <COL width="10%">'
		print '          <COL width="40%">'
		print '          <COL width="50%">'
		print '        </COLGROUP>'
		print '        <THEAD>'
		print '          <TR>'
		print '            <TD class="fullbox">Dom 0?</TD>'
		print '            <TD class="fullbox">Name</TD>'
		print '            <TD class="fullbox">Actions</TD>'
		print '          </TR>'
		print '        </THEAD>'
		for i, vmName in enumerate( formVmNames[1] ):
			print '        <TR>'
			print '          <TD class="fullbox">'
			if formVmNameDom0[1] == vmName:
				print 'Yes'
			else:
				print '&nbsp;'
			print '          </TD>'
			print '          <TD class="fullbox">' + vmName + '</TD>'
			print '          <TD class="fullbox">'
			print '            <A href="#' + vmName + '">Edit</A>'
			formVar = allVmDel[vmName]
			sendHtmlFormVar( formVar, 'class="link"' )
			formVar = allVmDom0[vmName]
			sendHtmlFormVar( formVar, 'class="link"' )
			print '          </TD>'
			print '        </TR>'
		print '      </TABLE>'
		print '    </TD>'
		print '  </TR>'
		for vmName in formVmNames[1]:
			print '  <TR>'
			print '    <TD>'
			print '      <HR>'
			print '    </TD>'
			print '  </TR>'
			print '  <TR>'
			print '    <TD>'
			print '      <TABLE class="full">'
			print '        <COLGROUP>'
			print '          <COL width="10%">'
			print '          <COL width="39%">'
			print '          <COL width="2%">'
			print '          <COL width="10%">'
			print '          <COL width="39%">'
			print '        </COLGROUP>'
			print '        <TR>'
			print '          <TD colspan="5" align="center" class="heading">'
			print '            <A name="' + vmName + '">Virtual Machine Class: ' + vmName + '</A>'
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD colspan="2" align="center">Simple Type Enforcement Types</TD>'
			print '          <TD>&nbsp;</TD>'
			print '          <TD colspan="2" align="center">Chinese Wall Types</TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD colspan="2">'
			formVar = allVmStes[vmName];
			sendHtmlFormVar( formVar, 'class="full" size="4" multiple"' )
			print '          </TD>'
			print '          <TD>&nbsp;</TD>'
			print '          <TD colspan="2">'
			formVar = allVmChWs[vmName];
			sendHtmlFormVar( formVar, 'class="full" size="4" multiple"' )
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD>'
			formVar = allVmSteDel[vmName];
			sendHtmlFormVar( formVar, 'class="full"' )
			print '          </TD>'
			print '          <TD>'
			print '            Delete the type(s) selected above'
			print '          </TD>'
			print '          <TD>&nbsp;</TD>'
			print '          <TD>'
			formVar = allVmChWDel[vmName];
			sendHtmlFormVar( formVar, 'class="full"' )
			print '          </TD>'
			print '          <TD>'
			print '            Delete the type(s) selected above'
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD colspan="2">'
			stSet = Set( formSteTypes[1] )
			vmSet = Set( allVmStes[vmName][1] )
			formVar = allVmSte[vmName]
			formVar[1] = []
			for steType in stSet.difference( vmSet ):
				formVar[1].append( steType )
			formVar[1].sort( )
			sendHtmlFormVar( formVar, 'class="full" size="2" multiple"' )
			print '          </TD>'
			print '          <TD>&nbsp;</TD>'
			print '          <TD colspan="2">'
			ctSet = Set( formChWallTypes[1] )
			vmSet = Set( allVmChWs[vmName][1] )
			formVar = allVmChW[vmName]
			formVar[1] = []
			for chwallType in ctSet.difference( vmSet ):
				formVar[1].append( chwallType )
			formVar[1].sort( )
			sendHtmlFormVar( formVar, 'class="full" size="2" multiple"' )
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD>'
			formVar = allVmSteAdd[vmName];
			sendHtmlFormVar( formVar, 'class="full"' )
			print '          </TD>'
			print '          <TD>'
			print '            Add the type(s) selected above'
			print '          </TD>'
			print '          <TD>&nbsp;</TD>'
			print '          <TD>'
			formVar = allVmChWAdd[vmName];
			sendHtmlFormVar( formVar, 'class="full"' )
			print '          </TD>'
			print '          <TD>'
			print '            Add the type(s) selected above'
			print '          </TD>'
			print '        </TR>'
			print '      </TABLE>'
			print '    </TD>'
			print '  </TR>'

	print '</TABLE>'

def sendPLObjHtml( ):

	# Resources...
	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="60%">'
	print '    <COL width="20%">'
	print '    <COL width="20%">'
	print '  </COLGROUP>'

	print '  <TR>'
	print '    <TD align="center" colspan="3" class="heading">Resources</TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD colspan="2">'
	#sendHtmlFormVar( formVmNames, 'class="full" size="4" multiple"' )
	print '    </TD>'
	print '    <TD>'
	#sendHtmlFormVar( formVmDel, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD colspan="2">'
	#sendHtmlFormVar( formVmName, 'class="full"' )
	print '    </TD>'
	print '    <TD>'
	#sendHtmlFormVar( formVmAdd, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '</TABLE>'

def checkXmlData( ):
	global xmlIncomplete

	# Validate the Policy Label Header requirements
	if ( len( formPolicyLabelName[1] ) == 0 ) or \
	   ( len( formPolicyLabelDate[1] ) == 0 ) or \
	   ( len( formPolicyUrl[1] ) == 0 ) or \
	   ( len( formPolicyRef[1] ) == 0 ):
			msg = ''
			msg = msg + 'The XML policy label schema requires that the Policy '
			msg = msg + 'Labeling Information Name, Date, Policy URL and '
			msg = msg + 'Policy Reference fields all have values.'
			formatXmlGenError( msg )

def sendXmlHeaders( ):
	# HTML headers
	print 'Content-Type: text/xml'
	print 'Content-Disposition: attachment; filename=security_label_template.xml'
	print

def sendPolicyLabelXml( ):
	print '<?xml version="1.0"?>'

	print '<SecurityLabelTemplate xmlns="http://www.ibm.com"'
	print '                       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
	print '                       xsi:schemaLocation="http://www.ibm.com security_policy.xsd">'

	# Policy Labeling header
	sendPLHeaderXml( )

	# Policy Labels (subjects and objects)
	sendPLSubXml( )
	#sendPLObjXml( )

	print '</SecurityLabelTemplate>'

def sendPLHeaderXml( ):
	global formPolicyLabelName, formPolicyLabelDate
	global formPolicyUrl, formPolicyRef

	# Policy Labeling header definition
	print '<LabelHeader>'
	print '  <Name>' + formPolicyLabelName[1] + '</Name>'
	print '  <Date>' + formPolicyLabelDate[1] + '</Date>'
	print '  <PolicyName>'
	print '    <Url>' + formPolicyUrl[1] + '</Url>'
	print '    <Reference>' + formPolicyRef[1] + '</Reference>'
	print '  </PolicyName>'
	print '</LabelHeader>'

def sendPLSubXml( ):
	global formVmNames, allVmChWs, allVmStes

	# Virtual machines...
	if len( formVmNames[1] ) == 0:
		return

	print '<SubjectLabels bootstrap="' + formVmNameDom0[1] + '">'
	for vmName in formVmNames[1]:
		print '  <VirtualMachineLabel>'
		print '    <Name>' + vmName + '</Name>'
		formVar = allVmStes[vmName]
		if len( formVar[1] ) > 0:
			print '    <SimpleTypeEnforcementTypes>'
			for ste in formVar[1]:
				print '      <Type>' + ste + '</Type>'
			print '    </SimpleTypeEnforcementTypes>'

		formVar = allVmChWs[vmName]
		if len( formVar[1] ) > 0:
			print '    <ChineseWallTypes>'
			for chw in formVar[1]:
				print '      <Type>' + chw + '</Type>'
			print '    </ChineseWallTypes>'

		print '  </VirtualMachineLabel>'

	print '</SubjectLabels>'


# Set up initial HTML variables
headTitle = 'Xen Policy Labeling Generation'

# Form variables
#   The format of these variables is as follows:
#   [ p0, p1, p2, p3, p4, p5 ]
#     p0 = input type
#     p1 = the current value of the variable
#     p2 = the hidden input name attribute
#     p3 = the name attribute
#     p4 = the value attribute
#     p5 = text to associate with the tag
formPolicyLabelName   = [ 'text',
			'',
			'h_policyLabelName',
			'i_policyLabelName',
			'',
			'',
			]
formPolicyLabelDate   = [ 'text',
			getCurrentTime( ),
			'h_policyLabelDate',
			'i_policyLabelDate',
			'',
			'',
			]
formPolicyUrl         = [ 'text',
			'',
			'h_policyUrl',
			'i_policyUrl',
			'',
			'',
			]
formPolicyRef         = [ 'text',
			'',
			'h_policyRef',
			'i_policyRef',
			'',
			'',
			]
formPolicyLabelUpdate = [ 'button',
			'',
			'',
			'i_PolicyLabelUpdate',
			'Update',
			'',
		    ]

formVmNames       = [ '',
			[],
			'h_vmNames',
			'',
			'',
			'',
		    ]
formVmDel         = [ 'button',
			'',
			'',
			'i_vmDel',
			'Delete',
			'',
		    ]
formVmName        = [ 'text',
			'',
			'',
			'i_vmName',
			'',
			'',
		    ]
formVmAdd         = [ 'button',
			'',
			'',
			'i_vmAdd',
			'New',
			'',
		    ]

formVmNameDom0    = [ '',
			'',
			'h_vmDom0',
			'',
			'',
			'',
		    ]

formXmlGen        = [ 'button',
			'',
			'',
			'i_xmlGen',
			'Generate XML',
			'',
		    ]

formDefaultButton = [ 'button',
			'',
			'',
			'i_defaultButton',
			'.',
			'',
		    ]

formSteTypes      = [ '',
                        [],
			'h_steTypes',
			'',
			'',
			'',
		    ]
formChWallTypes   = [ '',
                        [],
			'h_chwallTypes',
			'',
			'',
			'',
		    ]

# This is a set of templates used for each virtual machine
#   Each virtual machine is initially assigned these templates,
#   then each form attribute value is changed to append
#   "_virtual-machine-name" for uniqueness.
templateVmDel     = [ 'button',
			'',
			'',
			'i_vmDel',
			'Delete',
			'',
		    ]
templateVmDom0    = [ 'button',
			'',
			'',
			'i_vmDom0',
			'SetDom0',
			'',
		    ]
allVmDel          = {};
allVmDom0         = {};

templateVmChWs    = [ 'list',
			[],
			'h_vmChWs',
			'i_vmChWs',
			'',
			'',
		    ]
templateVmChWDel  = [ 'button',
			'',
			'',
			'i_vmChWDel',
			'Delete',
			'',
		    ]
templateVmChW     = [ 'list',
			[],
			'',
			'i_vmChW',
			'',
			'',
		    ]
templateVmChWAdd  = [ 'button',
			'',
			'',
			'i_vmChWAdd',
			'Add',
			'',
		    ]
allVmChWs         = {};
allVmChWDel       = {};
allVmChW          = {};
allVmChWAdd       = {};

templateVmStes    = [ 'list',
			[],
			'h_vmStes',
			'i_vmStes',
			'',
			'',
		    ]
templateVmSteDel  = [ 'button',
			'',
			'',
			'i_vmSteDel',
			'Delete',
			'',
		    ]
templateVmSte     = [ 'list',
			[],
			'',
			'i_vmSte',
			'',
			'',
		    ]
templateVmSteAdd  = [ 'button',
			'',
			'',
			'i_vmSteAdd',
			'Add',
			'',
		    ]
allVmStes         = {};
allVmSteDel       = {};
allVmSte          = {};
allVmSteAdd       = {};

# A list of all form variables used for saving info across requests
formVariables     = [ formPolicyLabelName,
			formPolicyLabelDate,
			formPolicyUrl,
			formPolicyRef,
			formVmNames,
			formVmNameDom0,
			formSteTypes,
			formChWallTypes,
		    ]

policyXml         = ''
policyLabelXml    = ''
xmlError          = 0
xmlIncomplete     = 0
xmlMessages       = []


# Extract any form data
formData = cgi.FieldStorage( )

# Process the form
getSavedData( )
processRequest( )

if formData.has_key( formXmlGen[3] ):
	# Generate and send the XML file
	checkXmlData( )

	if xmlIncomplete == 0:
		sendXmlHeaders( )
		sendPolicyLabelXml( )

if (not formData.has_key( formXmlGen[3] )) or (xmlIncomplete == 1 ):
	# Send HTML to continue processing the form
	sendHtmlHeaders( )
	sendPolicyLabelHtml( )
