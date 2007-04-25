#!/usr/bin/python
#
# The Initial Developer of the Original Code is International
# Business Machines Corporation. Portions created by IBM
# Corporation are Copyright (C) 2005, 2006 International Business
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
	global formData, policyXml
	global formVariables, formCSNames, formVmNames, formResNames
	global allCSMTypes, allVmChWs, allVmStes, allResStes

	# Process the XML upload policy file
	if formData.has_key( 'i_policy' ):
		dataList = formData.getlist( 'i_policy' )
		if len( dataList ) > 0:
			policyXml  = dataList[0]

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

	# The form can contain any number of "Conflict Sets"
	#   so update the list of form variables to include
	#   each conflict set (hidden input variable)
	for csName in formCSNames[1]:
		newCS( csName )
		if formData.has_key( allCSMTypes[csName][2] ):
			dataList = formData.getlist( allCSMTypes[csName][2] )
			if len( dataList ) > 0:
				exec 'allCSMTypes[csName][1] = ' + dataList[0]

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

	# The form can contain any number of "Resources"
	#   so update the list of form variables to include
	#   each resource (hidden input variable)
	for resName in formResNames[1]:
		newRes( resName )

		resFormVar = allResStes[resName]
		if (resFormVar[2] != '') and formData.has_key( resFormVar[2] ):
			dataList = formData.getlist( resFormVar[2] )
			if len( dataList ) > 0:
				if isinstance( resFormVar[1], list ):
					exec 'resFormVar[1] = ' + dataList[0]
				else:
					resFormVar[1] = dataList[0]


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

def getPolicyName( domNode ):
	nameNodes = domNode.getElementsByTagName( 'PolicyName' )
	if len( nameNodes ) == 0:
		formatXmlError( '"<PolicyName>" tag is missing' )
		return None

	name = ''
	for childNode in nameNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			name = name + childNode.data

	return name

def getUrl( domNode ):
	urlNodes = domNode.getElementsByTagName( 'PolicyUrl' )
	if len( urlNodes ) == 0:
		return ''

	url = ''
	for childNode in urlNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			url = url + childNode.data

	return url

def getRef( domNode ):
	refNodes = domNode.getElementsByTagName( 'Reference' )
	if len( refNodes ) == 0:
		return ''

	ref = ''
	for childNode in refNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			ref = ref + childNode.data

	return ref

def getDate( domNode ):
	dateNodes = domNode.getElementsByTagName( 'Date' )
	if len( dateNodes ) == 0:
		return ''

	date = ''
	for childNode in dateNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			date = date + childNode.data

	return date

def getNSUrl( domNode ):
	urlNodes = domNode.getElementsByTagName( 'NameSpaceUrl' )
	if len( urlNodes ) == 0:
		return ''

	url = ''
	for childNode in urlNodes[0].childNodes:
		if childNode.nodeType == xml.dom.Node.TEXT_NODE:
			url = url + childNode.data

	return url

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
	xmlParser = xml.sax.make_parser( )
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
	global formPolicyName, formPolicyUrl, formPolicyRef, formPolicyDate, formPolicyNSUrl
	global formPolicyOrder
	global formSteTypes, formChWallTypes, formVmNames, formVmNameDom0
	global allCSMTypes, allVmStes, allVmChWs

	domDoc = parseXml( policyXml )
	if domDoc == None:
		return

	# Process the PolicyHeader
	domRoot    = domDoc.documentElement
	domHeaders = domRoot.getElementsByTagName( 'PolicyHeader' )
	if len( domHeaders ) == 0:
		msg = ''
		msg = msg + '"<PolicyHeader>" tag is missing.\n'
		msg = msg + 'Please validate the Policy file used.'
		formatXmlError( msg )
		return

	pName = getPolicyName( domHeaders[0] )
	if pName == None:
		msg = ''
		msg = msg + 'Error processing the Policy header information.\n'
		msg = msg + 'Please validate the Policy file used.'
		formatXmlError( msg )
		return

	formPolicyName[1]  = pName
	formPolicyUrl[1]   = getUrl( domHeaders[0] )
	formPolicyRef[1]   = getRef( domHeaders[0] )
	formPolicyDate[1]  = getDate( domHeaders[0] )
	formPolicyNSUrl[1] = getNSUrl( domHeaders[0] )

	# Process the STEs
	pOrder = ''
	domStes = domRoot.getElementsByTagName( 'SimpleTypeEnforcement' )
	if len( domStes ) > 0:
		if domStes[0].hasAttribute( 'priority' ):
			if domStes[0].getAttribute( 'priority' ) != 'PrimaryPolicyComponent':
				msg = ''
				msg = msg + 'Error processing the "<SimpleTypeEnforcement>" tag.\n'
				msg = msg + 'The "priority" attribute value is not valid.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			pOrder = 'v_Ste'

		steTypes = getSteTypes( domStes[0], 1 )
		if steTypes == None:
			msg = ''
			msg = msg + 'Error processing the SimpleTypeEnforcement types.\n'
			msg = msg + 'Please validate the Policy file used.'
			formatXmlError( msg )
			return

		formSteTypes[1] = steTypes

	# Process the ChineseWalls and Conflict Sets
	domChWalls = domRoot.getElementsByTagName( 'ChineseWall' )
	if len( domChWalls ) > 0:
		if domChWalls[0].hasAttribute( 'priority' ):
			if domChWalls[0].getAttribute( 'priority' ) != 'PrimaryPolicyComponent':
				msg = ''
				msg = msg + 'Error processing the "<ChineseWall>" tag.\n'
				msg = msg + 'The "priority" attribute value is not valid.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			if pOrder != '':
				msg = ''
				msg = msg + 'Error processing the "<ChineseWall>" tag.\n'
				msg = msg + 'The "priority" attribute has been previously specified.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			pOrder = 'v_ChWall'

		chwTypes = getChWTypes( domChWalls[0], 1 )
		if chwTypes == None:
			msg = ''
			msg = msg + 'Error processing the ChineseWall types.\n'
			msg = msg + 'Please validate the Policy file used.'
			formatXmlError( msg )
			return

		formChWallTypes[1] = chwTypes

		csNodes = domChWalls[0].getElementsByTagName( 'ConflictSets' )
		if csNodes and (len( csNodes ) > 0):
			cNodes = csNodes[0].getElementsByTagName( 'Conflict' )
			if not cNodes or len( cNodes ) == 0:
				msg = ''
				msg = msg + 'Required "<Conflict>" tag missing.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			for cNode in cNodes:
				csName = cNode.getAttribute( 'name' )
				newCS( csName, 1 )

				csMemberList = getTypes( cNode )
				if csMemberList == None:
					msg = ''
					msg = msg + 'Error processing the Conflict Set members.\n'
					msg = msg + 'Please validate the Policy file used.'
					formatXmlError( msg )
					return

				# Verify the conflict set members are valid types
				ctSet = Set( formChWallTypes[1] )
				csSet = Set( csMemberList )
				if not csSet.issubset( ctSet ):
					msg = ''
					msg = msg + 'Error processing Conflict Set "' + csName + '".\n'
					msg = msg + 'Members of the conflict set are not valid '
					msg = msg + 'Chinese Wall types.\n'
					msg = msg + 'Please validate the Policy file used.'
					formatXmlError( msg )

				allCSMTypes[csName][1] = csMemberList

	if pOrder != '':
		formPolicyOrder[1] = pOrder
	else:
		if (len( domStes ) > 0) or (len( domChWalls ) > 0):
			msg = ''
			msg = msg + 'The "priority" attribute has not been specified.\n'
			msg = msg + 'It must be specified on one of the access control types.\n'
			msg = msg + 'Please validate the Policy file used.'
			formatXmlError( msg )
			return

	# Process the Labels
	domLabels = domRoot.getElementsByTagName( 'SecurityLabelTemplate' )
	if not domLabels or (len( domLabels ) == 0):
		msg = ''
		msg = msg + '<SecurityLabelTemplate> tag is missing.\n'
		msg = msg + 'Please validate the Policy file used.'
		formatXmlError( msg )
		return


	# Process the VMs
	domSubjects = domLabels[0].getElementsByTagName( 'SubjectLabels' )
	if len( domSubjects ) > 0:
		formVmNameDom0[1] = domSubjects[0].getAttribute( 'bootstrap' )
		domNodes = domSubjects[0].getElementsByTagName( 'VirtualMachineLabel' )
		for domNode in domNodes:
			vmName = getName( domNode )
			if vmName == None:
				msg = ''
				msg = msg + 'Error processing the VirtualMachineLabel name.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				continue

			steTypes = getSteTypes( domNode )
			if steTypes == None:
				msg = ''
				msg = msg + 'Error processing the SimpleTypeEnforcement types.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			chwTypes = getChWTypes( domNode )
			if chwTypes == None:
				msg = ''
				msg = msg + 'Error processing the ChineseWall types.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			newVm( vmName, 1 )
			allVmStes[vmName][1] = steTypes
			allVmChWs[vmName][1] = chwTypes

	# Process the Resources
	domObjects = domLabels[0].getElementsByTagName( 'ObjectLabels' )
	if len( domObjects ) > 0:
		domNodes = domObjects[0].getElementsByTagName( 'ResourceLabel' )
		for domNode in domNodes:
			resName = getName( domNode )
			if resName == None:
				msg = ''
				msg = msg + 'Error processing the ResourceLabel name.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				continue

			steTypes = getSteTypes( domNode )
			if steTypes == None:
				msg = ''
				msg = msg + 'Error processing the SimpleTypeEnforcement types.\n'
				msg = msg + 'Please validate the Policy file used.'
				formatXmlError( msg )
				return

			newRes( resName, 1 )
			allResStes[resName][1] = steTypes

def modFormTemplate( formTemplate, suffix ):
	formVar = [x for x in formTemplate]

	if formVar[2] != '':
		formVar[2] = formVar[2] + suffix
	if formVar[3] != '':
		formVar[3] = formVar[3] + suffix
	if (formVar[0] != 'button') and (formVar[4] != ''):
		formVar[4] = formVar[4] + suffix

	return formVar;

def removeDups( curList ):
	newList = []
	curSet  = Set( curList )
	for x in curSet:
		newList.append( x )
	newList.sort( )

	return newList

def newCS( csName, addToList = 0 ):
	global formCSNames
	global templateCSDel, allCSDel
	global templateCSMTypes, templateCSMDel, templateCSMType, templateCSMAdd
	global allCSMTypes, allCSMDel, allCSMType, allCSMAdd

	csSuffix = '_' + csName

	# Make sure we have an actual name and check one of the 'all'
	# variables to be sure it hasn't been previously defined
	if (len( csName ) > 0) and (not allCSMTypes.has_key( csName )):
		allCSDel[csName]    = modFormTemplate( templateCSDel,    csSuffix )
		allCSMTypes[csName] = modFormTemplate( templateCSMTypes, csSuffix )
		allCSMDel[csName]   = modFormTemplate( templateCSMDel,   csSuffix )
		allCSMType[csName]  = modFormTemplate( templateCSMType,  csSuffix )
		allCSMAdd[csName]   = modFormTemplate( templateCSMAdd,   csSuffix )
		if addToList == 1:
			formCSNames[1].append( csName )
			formCSNames[1] = removeDups( formCSNames[1] )

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

def newRes( resName, addToList = 0 ):
	global formResNames
	global templateResDel, allResDel
	global templateResStes, templateResSteDel, templateResSte, templateResSteAdd
	global allResStes, allResSteDel, allResSteType, allResSteAdd

	# Make sure we have an actual name and check one of the 'all'
	# variables to be sure it hasn't been previously defined
	if (len( resName ) > 0) and (not allResDel.has_key( resName )):
		resSuffix = '_' + resName
		allResDel[resName]    = modFormTemplate( templateResDel,    resSuffix )
		allResStes[resName]   = modFormTemplate( templateResStes,   resSuffix )
		allResSteDel[resName] = modFormTemplate( templateResSteDel, resSuffix )
		allResSte[resName]    = modFormTemplate( templateResSte,    resSuffix )
		allResSteAdd[resName] = modFormTemplate( templateResSteAdd, resSuffix )
		if addToList == 1:
			formResNames[1].append( resName )
			formResNames[1] = removeDups( formResNames[1] )

def updateInfo( ):
	global formData, formPolicyName, formPolicyUrl, formPolicyRef, formPolicyDate, formPolicyNSUrl
	global formPolicyOrder

	if formData.has_key( formPolicyName[3] ):
		formPolicyName[1] = formData[formPolicyName[3]].value
	elif formData.has_key( formPolicyUpdate[3] ):
		formPolicyName[1] = ''

	if formData.has_key( formPolicyUrl[3] ):
		formPolicyUrl[1] = formData[formPolicyUrl[3]].value
	elif formData.has_key( formPolicyUpdate[3] ):
		formPolicyUrl[1] = ''

	if formData.has_key( formPolicyRef[3] ):
		formPolicyRef[1] = formData[formPolicyRef[3]].value
	elif formData.has_key( formPolicyUpdate[3] ):
		formPolicyRef[1] = ''

	if formData.has_key( formPolicyDate[3] ):
		formPolicyDate[1] = formData[formPolicyDate[3]].value
	elif formData.has_key( formPolicyUpdate[3] ):
		formPolicyDate[1] = ''

	if formData.has_key( formPolicyNSUrl[3] ):
		formPolicyNSUrl[1] = formData[formPolicyNSUrl[3]].value
	elif formData.has_key( formPolicyUpdate[3] ):
		formPolicyNSUrl[1] = ''

	if formData.has_key( formPolicyOrder[3] ):
		formPolicyOrder[1] = formData[formPolicyOrder[3]].value

def addSteType( ):
	global formData, formSteType, formSteTypes

	if (formData.has_key( formDefaultButton[3] )) or (formData.has_key( formSteAdd[3] )):
		if formData.has_key( formSteType[3] ):
			type = formData[formSteType[3]].value
			type = type.strip( )
			if len( type ) > 0:
				formSteTypes[1].append( type )
				formSteTypes[1] = removeDups( formSteTypes[1] )


def delSteType( ):
	global formData, formSteTypes

	if formData.has_key( formSteTypes[3] ):
		typeList = formData.getlist( formSteTypes[3] )
		for type in typeList:
			type = type.strip( )
			formSteTypes[1].remove( type )

def addChWallType( ):
	global formData, formChWallType, formChWallTypes

	if (formData.has_key( formDefaultButton[3] )) or (formData.has_key( formChWallAdd[3] )):
		if formData.has_key( formChWallType[3] ):
			type = formData[formChWallType[3]].value
			type = type.strip( )
			if len( type ) > 0:
				formChWallTypes[1].append( type )
				formChWallTypes[1] = removeDups( formChWallTypes[1] )

def delChWallType( ):
	global formData, formChWallTypes

	if formData.has_key( formChWallTypes[3] ):
		typeList = formData.getlist( formChWallTypes[3] )
		for type in typeList:
			type = type.strip( )
			formChWallTypes[1].remove( type )

def addCS( ):
	global formData, formCSNames

	if (formData.has_key( formDefaultButton[3] )) or (formData.has_key( formCSAdd[3] )):
		if formData.has_key( formCSName[3] ):
			csName = formData[formCSName[3]].value
			csName = csName.strip( )
			newCS( csName, 1 )

def delCS( csName ):
	global formData, formCSNames, allCSDel
	global allCSMTypes, allCSMDel, allCSMType, allCSMAdd

	csName = csName.strip( )
	formCSNames[1].remove( csName )
	del allCSDel[csName]
	del allCSMTypes[csName]
	del allCSMDel[csName]
	del allCSMType[csName]
	del allCSMAdd[csName]

def addCSMember( csName ):
	global formData, allCSMType, allCSMTypes

	formVar = allCSMType[csName]
	if formData.has_key( formVar[3] ):
		csmList = formData.getlist( formVar[3] )
		formVar = allCSMTypes[csName]
		for csm in csmList:
			csm = csm.strip( )
			formVar[1].append( csm )
			formVar[1] = removeDups( formVar[1] )

def delCSMember( csName ):
	global formData, allCSMTypes

	formVar = allCSMTypes[csName]
	if formData.has_key( formVar[3] ):
		csmList = formData.getlist( formVar[3] )
		for csm in csmList:
			csm = csm.strip( )
			formVar[1].remove( csm )

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

def addVmChW( vmName ):
	global formData, allVmChW, allVmChWs

	formVar = allVmChW[vmName]
	if formData.has_key( formVar[3] ):
		chwList = formData.getlist( formVar[3] )
		formVar = allVmChWs[vmName]
		for chw in chwList:
			chw = chw.strip( )
			formVar[1].append( chw )
			formVar[1] = removeDups( formVar[1] )

def delVmChW( vmName ):
	global formData, allVmChWs

	formVar = allVmChWs[vmName]
	if formData.has_key( formVar[3] ):
		chwList = formData.getlist( formVar[3] )
		for chw in chwList:
			chw = chw.strip( )
			formVar[1].remove( chw )

def addVmSte( vmName ):
	global formData, allVmSte, allVmStes

	formVar = allVmSte[vmName]
	if formData.has_key( formVar[3] ):
		steList = formData.getlist( formVar[3] )
		formVar = allVmStes[vmName]
		for ste in steList:
			ste = ste.strip( )
			formVar[1].append( ste )
			formVar[1] = removeDups( formVar[1] )

def delVmSte( vmName ):
	global formData, allVmStes

	formVar = allVmStes[vmName]
	if formData.has_key( formVar[3] ):
		steList = formData.getlist( formVar[3] )
		for ste in steList:
			ste = ste.strip( )
			formVar[1].remove( ste )

def addRes( ):
	global formData, fromResName, formResNames

	if (formData.has_key( formDefaultButton[3] )) or (formData.has_key( formResAdd[3] )):
		if formData.has_key( formResName[3] ):
			resName = formData[formResName[3]].value
			resName = resName.strip( )
			newRes( resName, 1 )

def delRes( resName ):
	global formResNames
	global allResDel
	global allResStes, allResSteDel, allResSteType, allResSteAdd

	resName = resName.strip( )
	formResNames[1].remove( resName )
	del allResDel[resName]
	del allResStes[resName]
	del allResSteDel[resName]
	del allResSte[resName]
	del allResSteAdd[resName]

def addResSte( vmName ):
	global formData, allResSte, allResStes

	formVar = allResSte[vmName]
	if formData.has_key( formVar[3] ):
		steList = formData.getlist( formVar[3] )
		formVar = allResStes[vmName]
		for ste in steList:
			ste = ste.strip( )
			formVar[1].append( ste )
			formVar[1] = removeDups( formVar[1] )

def delResSte( vmName ):
	global formData, allResStes

	formVar = allResStes[vmName]
	if formData.has_key( formVar[3] ):
		steList = formData.getlist( formVar[3] )
		for ste in steList:
			ste = ste.strip( )
			formVar[1].remove( ste )

def processRequest( ):
	global policyXml
	global formData, formPolicyUpdate
	global formSteAdd, formSteDel
	global formChWallAdd, formChWallDel
	global formCSAdd, allCSDel
	global formCSNames, allCSMAdd, allCSMDel
	global formVmAdd
	global formVmNames, allVmDel, allVmDom0
	global allVmChWAdd, allVmChWDel, allVmSteAdd, allVmSteDel
	global formResAdd
	global formResNames, allResDel
	global allResSteAdd, allResSteDel

	if policyXml != '':
		parsePolicyXml( )

	# Allow the updating of the header information whenever
	# an action is performed
	updateInfo( )

	# Allow the adding of types/sets/vms if the user has hit the
	# enter key when attempting to add a type/set/vm
	addSteType( )
	addChWallType( )
	addCS( )
	addVm( )
	addRes( )

	if formData.has_key( formSteDel[3] ):
		delSteType( )

	elif formData.has_key( formChWallDel[3] ):
		delChWallType( )

	else:
		for csName in formCSNames[1]:
			if formData.has_key( allCSDel[csName][3] ):
				delCS( csName )
				continue

			if formData.has_key( allCSMAdd[csName][3] ):
				addCSMember( csName )

			elif formData.has_key( allCSMDel[csName][3] ):
				delCSMember( csName )

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

	for resName in formResNames[1]:
		if formData.has_key( allResDel[resName][3] ):
			delRes( resName )
			continue

		if formData.has_key( allResSteAdd[resName][3] ):
			addResSte( resName )

		elif formData.has_key( allResSteDel[resName][3] ):
			delResSte( resName )

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
			buttonTexts = formVar[5]
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

				print '<INPUT type="radio"', nameAttr, valueAttr, addAttrs, checked, '>', htmlText, '<BR>'

	if ( formVar[2] != '' ) and ( rb_select == 0 ):
		nameAttr = makeNameAttr( formVar[2] )
		valueAttr = makeValueAttr( formVar[1] )
		print '<INPUT type="hidden"', nameAttr, valueAttr, '>'

def sendHtmlHeaders( ):
	# HTML headers
	print 'Content-Type: text/html'
	print

def sendPolicyHtml( ):
	global xmlError, xmlIncomplete, xmlMessages
	global formDefaultButton, formXmlGen
	global formVmNameDom0

	print '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"'
	print '  "http://www.w3.org/TR/html4/loose.dtd">'

	print '<HTML>'

	sendHtmlHead( )

	print '<BODY>'

	# An input XML file was specified that had errors, output the
	# error information
	if xmlError == 1:
		print '<P>'
		print 'An error has been encountered while processing the input '
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
	print '      <TABLE>'
	print '        <TR>'
	print '          <TD>'
	sendHtmlFormVar( formDefaultButton, 'class="hidden"' )
	print '          </TD>'
	print '        </TR>'
	print '        <TR>'
	print '          <TD>'
	sendHtmlFormVar( formXmlGen )
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'

	# Policy header
	print '  <TR>'
	print '    <TD>'
	sendPHeaderHtml( )
	print '    </TD>'
	print '  </TR>'

	# Separator
	print '  <TR><TD><HR></TD></TR>'

	# Policy (types)
	print '  <TR>'
	print '    <TD>'
	print '      <TABLE class="full">'
	print '        <COLGROUP>'
	print '          <COL width="49%">'
	print '          <COL width="2%">'
	print '          <COL width="49%">'
	print '        </COLGROUP>'
	print '        <TR>'
	print '          <TD>'
	sendPSteHtml( )
	print '          </TD>'
	print '          <TD>&nbsp;</TD>'
	print '          <TD>'
	sendPChWallHtml( )
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
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
	print '        <COLGROUP>'
	print '          <COL width="100%">'
	print '        </COLGROUP>'
	print '        <TR>'
	print '          <TD>'
	sendPLSubHtml( )
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'

	# Separator
	print '  <TR>'
	print '    <TD>'
	print '      <HR>'
	print '    </TD>'
	print '  </TR>'

	# Policy Labels (resources)
	print '  <TR>'
	print '    <TD>'
	print '      <TABLE class="full">'
	print '        <COLGROUP>'
	print '          <COL width="100%">'
	print '        </COLGROUP>'
	print '        <TR>'
	print '          <TD>'
	sendPLObjHtml( )
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'

	print '</TABLE>'

	# Send some data that needs to be available across sessions
	sendHtmlFormVar( formVmNameDom0 )

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

def sendPHeaderHtml( ):
	global formPolicyName, formPolicyUrl, formPolicyRef, formPolicyDate, formPolicyNSUrl
	global formPolicyOrder, formPolicyUpdate

	# Policy header definition
	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="20%">'
	print '    <COL width="80%">'
	print '  </COLGROUP>'
	print '  <TR>'
	print '    <TD align="center" colspan="2" class="heading">Policy Information</TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Name:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyName, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Url:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyUrl, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Reference:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyRef, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Date:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyDate, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">NameSpace URL:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyNSUrl, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="right">Primary Policy:</TD>'
	print '    <TD align="left">'
	sendHtmlFormVar( formPolicyOrder )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="center" colspan="2">'
	sendHtmlFormVar( formPolicyUpdate )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD align="center" colspan="2" class="subheading">'
	print '      (The Policy Information is updated whenever an action is performed'
	print '       or it can be updated separately using the "Update" button)'
	print '    </TD>'
	print '  </TR>'
	print '</TABLE>'

def sendPSteHtml( ):
	global formSteTypes, formSteDel, formSteType, formSteAdd

	# Simple Type Enforcement...
	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="20%">'
	print '    <COL width="80%">'
	print '  </COLGROUP>'
	print '  <TR>'
	print '    <TD align="center" colspan="2" class="heading">Simple Type Enforcement Types</TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD colspan="2">'
	sendHtmlFormVar( formSteTypes, 'class="full" size="4" multiple' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD>'
	sendHtmlFormVar( formSteDel, 'class="full"' )
	print '    </TD>'
	print '    <TD>'
	print '      Delete the type(s) selected above'
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD colspan="2">'
	sendHtmlFormVar( formSteType, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD>'
	sendHtmlFormVar( formSteAdd, 'class="full"' )
	print '    </TD>'
	print '    <TD>'
	print '      Create a new type with the above name'
	print '    </TD>'
	print '  </TR>'
	print '</TABLE>'

def sendPChWallHtml( ):
	global formChWallTypes, formChWallDel, formChWallType, formChWallAdd
	global formCSNames, formCSName, formCSAdd, allCSDel
	global allCSMTypes, allCSMDel, allCSMType, allCSMAdd

	# Chinese Wall...
	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="20%">'
	print '    <COL width="80%">'
	print '  </COLGROUP>'
	print '  <TR>'
	print '    <TD align="center" colspan="2" class="heading">Chinese Wall Types</TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD colspan="2">'
	sendHtmlFormVar( formChWallTypes, 'class="full" size="4" multiple' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD>'
	sendHtmlFormVar( formChWallDel, 'class="full"' )
	print '    </TD>'
	print '    <TD>'
	print '      Delete the type(s) selected above'
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD colspan="2">'
	sendHtmlFormVar( formChWallType, 'class="full"' )
	print '    </TD>'
	print '  </TR>'
	print '  <TR>'
	print '    <TD>'
	sendHtmlFormVar( formChWallAdd, 'class="full"' )
	print '    </TD>'
	print '    <TD>'
	print '      Create a new type with the above name'
	print '    </TD>'
	print '  </TR>'

	# Chinese Wall Conflict Sets...
	print '  <TR>'
	print '    <TD colspan="2">'
	print '      <TABLE class="full">'
	print '        <COLGROUP>'
	print '          <COL width="20%">'
	print '          <COL width="30%">'
	print '          <COL width="50%">'
	print '        </COLGROUP>'
	print '        <THEAD>'
	print '          <TR>'
	print '            <TD align="center" colspan="3"><HR></TD>'
	print '          </TR>'
	print '          <TR>'
	print '            <TD align="center" colspan="3">Chinese Wall Conflict Sets</TD>'
	print '          </TR>'
	print '        </THEAD>'
	print '        <TR>'
	print '          <TD colspan="3">'
	sendHtmlFormVar( formCSName, 'class="full"' )
	sendHtmlFormVar( formCSNames )
	print '          </TD>'
	print '        </TR>'
	print '        <TR>'
	print '          <TD>'
	sendHtmlFormVar( formCSAdd, 'class="full"' )
	print '          </TD>'
	print '          <TD colspan="2">'
	print '            Create a new conflict set with the above name'
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'
	if len( formCSNames[1] ) > 0:
		print '  <TR>'
		print '    <TD colspan="2">'
		print '      &nbsp;'
		print '    </TD>'
		print '  </TR>'
		print '  <TR>'
		print '    <TD colspan="2">'
		print '      <TABLE class="fullbox">'
		print '        <COLGROUP>'
		print '          <COL width="50%">'
		print '          <COL width="50%">'
		print '        </COLGROUP>'
		print '        <THEAD>'
		print '          <TR>'
		print '            <TD class="fullbox">Name</TD>'
		print '            <TD class="fullbox">Actions</TD>'
		print '          </TR>'
		print '        </THEAD>'
		for i, csName in enumerate( formCSNames[1] ):
			print '        <TR>'
			print '          <TD class="fullbox">' + csName + '</TD>'
			print '          <TD class="fullbox">'
			print '            <A href="#' + csName + '">Edit</A>'
			formVar = allCSDel[csName]
			sendHtmlFormVar( formVar, 'class="link"' )
			print '          </TD>'
		print '      </TABLE>'
		print '    </TD>'
		print '  </TR>'
		for csName in formCSNames[1]:
			print '  <TR><TD colspan="2"><HR></TD></TR>'
			print '  <TR>'
			print '    <TD align="center" colspan="2" class="heading"><A name="' + csName + '">Conflict Set: ' + csName + '</A></TD>'
			print '  </TR>'
			print '  <TR>'
			print '    <TD colspan="2">'
			formVar = allCSMTypes[csName];
			sendHtmlFormVar( formVar, 'class="full" size="4" multiple"' )
			print '    </TD>'
			print '  </TR>'
			print '  <TR>'
			print '    <TD>'
			formVar = allCSMDel[csName]
			sendHtmlFormVar( formVar, 'class="full"' )
			print '    </TD>'
			print '    <TD>'
			print '      Delete the type(s) selected above'
			print '    </TD>'
			print '  </TR>'
			print '  <TR>'
			print '    <TD colspan="2">'
			ctSet = Set( formChWallTypes[1] )
			csSet = Set( allCSMTypes[csName][1] )
			formVar = allCSMType[csName]
			formVar[1] = []
			for chwallType in ctSet.difference( csSet ):
				formVar[1].append( chwallType )
			formVar[1].sort( )
			sendHtmlFormVar( formVar, 'class="full" size="2" multiple' )
			print '    </TD>'
			print '  </TR>'
			print '  <TR>'
			print '    <TD>'
			formVar = allCSMAdd[csName]
			sendHtmlFormVar( formVar, 'class="full"' )
			print '    </TD>'
			print '    <TD>'
			print '      Add the type(s) selected above'
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
	global formResNames, formResDel, formResName, formResAdd
	global allResDel
	global allResStes, allResSteDel, allResSte, allResSteAdd
	global formSteTypes, formChWallTypes

	print '<TABLE class="full">'
	print '  <COLGROUP>'
	print '    <COL width="100%">'
	print '  </COLGROUP>'

	# Resources...
	print '  <TR>'
	print '    <TD>'
	print '      <TABLE class="full">'
	print '        <COLGROUP>'
	print '          <COL width="10%">'
	print '          <COL width="40%">'
	print '          <COL width="50%">'
	print '        </COLGROUP>'
	print '        <TR>'
	print '          <TD class="heading" align="center" colspan="3">Resource Classes</TD>'
	print '        </TR>'
	print '        <TR>'
	print '          <TD colspan="2">'
	sendHtmlFormVar( formResName, 'class="full"' )
	sendHtmlFormVar( formResNames )
	print '          </TD>'
	print '          <TD>&nbsp;</TD>'
	print '        </TR>'
	print '        <TR>'
	print '          <TD>'
	sendHtmlFormVar( formResAdd, 'class="full"' )
	print '          </TD>'
	print '          <TD colspan="2">'
	print '            Create a new Resource class with the above name'
	print '          </TD>'
	print '        </TR>'
	print '      </TABLE>'
	print '    </TD>'
	print '  </TR>'
	if len( formResNames[1] ) > 0:
		print '  <TR>'
		print '    <TD colspan="1">'
		print '      &nbsp;'
		print '    </TD>'
		print '  </TR>'
		print '  <TR>'
		print '    <TD>'
		print '      <TABLE class="fullbox">'
		print '        <COLGROUP>'
		print '          <COL width="50%">'
		print '          <COL width="50%">'
		print '        </COLGROUP>'
		print '        <THEAD>'
		print '          <TR>'
		print '            <TD class="fullbox">Name</TD>'
		print '            <TD class="fullbox">Actions</TD>'
		print '          </TR>'
		print '        </THEAD>'
		for i, resName in enumerate( formResNames[1] ):
			print '        <TR>'
			print '          <TD class="fullbox">' + resName + '</TD>'
			print '          <TD class="fullbox">'
			print '            <A href="#' + resName + '">Edit</A>'
			formVar = allResDel[resName]
			sendHtmlFormVar( formVar, 'class="link"' )
			print '          </TD>'
			print '        </TR>'
		print '      </TABLE>'
		print '    </TD>'
		print '  </TR>'
		for resName in formResNames[1]:
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
			print '          <COL width="90%">'
			print '        </COLGROUP>'
			print '        <TR>'
			print '          <TD colspan="2" align="center" class="heading">'
			print '            <A name="' + resName + '">Resource Class: ' + resName + '</A>'
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD colspan="2" align="center">Simple Type Enforcement Types</TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD colspan="2">'
			formVar = allResStes[resName];
			sendHtmlFormVar( formVar, 'class="full" size="4" multiple"' )
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD>'
			formVar = allResSteDel[resName];
			sendHtmlFormVar( formVar, 'class="full"' )
			print '          </TD>'
			print '          <TD>'
			print '            Delete the type(s) selected above'
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD colspan="2">'
			stSet = Set( formSteTypes[1] )
			resSet = Set( allResStes[resName][1] )
			formVar = allResSte[resName]
			formVar[1] = []
			for steType in stSet.difference( resSet ):
				formVar[1].append( steType )
			formVar[1].sort( )
			sendHtmlFormVar( formVar, 'class="full" size="2" multiple"' )
			print '          </TD>'
			print '        </TR>'
			print '        <TR>'
			print '          <TD>'
			formVar = allResSteAdd[resName];
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

def checkXmlData( ):
	global xmlIncomplete
	global formPolicyName, formPolicyOrder
	global formChWallTypes, formSteTypes, formCSNames

	# Validate the Policy Header requirements
	if ( len( formPolicyName[1] ) == 0 ):
		msg = ''
		msg = msg + 'The XML policy schema requires that the Policy '
		msg = msg + 'Information Name field have a value.'
		formatXmlGenError( msg )

	if formPolicyOrder[1] == 'v_ChWall':
		if len( formChWallTypes[1] ) == 0:
			msg = ''
			msg = msg + 'You have specified the primary policy to be '
			msg = msg + 'Chinese Wall but have not created any Chinese '
			msg = msg + 'Wall types.  Please create some Chinese Wall '
			msg = msg + 'types or change the primary policy.'
			formatXmlGenError( msg )

	if formPolicyOrder[1] == 'v_Ste':
		if len( formSteTypes[1] ) == 0:
			msg = ''
			msg = msg + 'You have specified the primary policy to be '
			msg = msg + 'Simple Type Enforcement but have not created '
			msg = msg + 'any Simple Type Enforcement types.  Please create '
			msg = msg + 'some Simple Type Enforcement types or change the '
			msg = msg + 'primary policy.'
			formatXmlGenError( msg )

def sendXmlHeaders( ):
	# HTML headers
	print 'Content-Type: text/xml'
	print 'Content-Disposition: attachment; filename=security_policy.xml'
	print

def sendPolicyXml( ):
	print '<?xml version="1.0"?>'

	print '<SecurityPolicyDefinition xmlns="http://www.ibm.com"'
	print '                          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
	print '                          xsi:schemaLocation="http://www.ibm.com security_policy.xsd">'

	# Policy header
	sendPHeaderXml( )

	# Policy (types)
	sendPSteXml( )
	sendPChWallXml( )

	# Policy Labels (subjects and objects)
	print '<SecurityLabelTemplate>'
	sendPLSubXml( )
	sendPLObjXml( )
	print '</SecurityLabelTemplate>'
	print '</SecurityPolicyDefinition>'

def sendPHeaderXml( ):
	global formPolicyName, formPolicyUrl, formPolicyRef, formPolicyDate, formPolicyNSUrl

	# Policy header definition
	print '<PolicyHeader>'
	print '  <PolicyName>' + formPolicyName[1] + '</PolicyName>'
	print '  <Version>1.0</Version>'
	if len( formPolicyUrl[1] ) > 0:
		print '  <PolicyUrl>' + formPolicyUrl[1] + '</PolicyUrl>'
	if len( formPolicyRef[1] ) > 0:
		print '  <Reference>' + formPolicyRef[1] + '</Reference>'
	if len( formPolicyDate[1] ) > 0:
		print '  <Date>' + formPolicyDate[1] + '</Date>'
	if len( formPolicyNSUrl[1] ) > 0:
		print '  <NameSpaceUrl>' + formPolicyNSUrl[1] + '</NameSpaceUrl>'
	print '</PolicyHeader>'

def sendPSteXml( ):
	global formPolicyOrder, formSteTypes

	# Simple Type Enforcement...
	if len( formSteTypes[1] ) == 0:
		return

	if formPolicyOrder[1] == 'v_Ste':
		print '<SimpleTypeEnforcement priority="PrimaryPolicyComponent">'
	else:
		print '<SimpleTypeEnforcement>'

	print '  <SimpleTypeEnforcementTypes>'
	for steType in formSteTypes[1]:
		print '    <Type>' + steType + '</Type>'
	print '  </SimpleTypeEnforcementTypes>'

	print '</SimpleTypeEnforcement>'

def sendPChWallXml( ):
	global formPolicyOrder, formChWallTypes
	global formCSNames, allCSMTypes

	# Chinese Wall...
	if len( formChWallTypes[1] ) == 0:
		return

	if formPolicyOrder[1] == 'v_ChWall':
		print '<ChineseWall priority="PrimaryPolicyComponent">'
	else:
		print '<ChineseWall>'

	print '  <ChineseWallTypes>'
	for chWallType in formChWallTypes[1]:
		print '    <Type>' + chWallType + '</Type>'
	print '  </ChineseWallTypes>'

	# Chinese Wall Conflict Sets (if any) ...
	if len( formCSNames[1] ) > 0:
		print '  <ConflictSets>'
		for cs in formCSNames[1]:
			formVar = allCSMTypes[cs]
			if len( formVar[1] ) == 0:
				continue
			print '    <Conflict name="' + cs + '">'
			for csm in formVar[1]:
				print '      <Type>' + csm + '</Type>'
			print '    </Conflict>'
		print '  </ConflictSets>'

	print '</ChineseWall>'

def sendPLSubXml( ):
	global formVmNames, allVmChWs, allVmStes

	# Virtual machines...
	if len( formVmNames[1] ) == 0:
		return

	print '  <SubjectLabels bootstrap="' + formVmNameDom0[1] + '">'
	for vmName in formVmNames[1]:
		print '    <VirtualMachineLabel>'
		print '      <Name>' + vmName + '</Name>'
		formVar = allVmStes[vmName]
		if len( formVar[1] ) > 0:
			print '      <SimpleTypeEnforcementTypes>'
			for ste in formVar[1]:
				print '      <Type>' + ste + '</Type>'
			print '      </SimpleTypeEnforcementTypes>'

		formVar = allVmChWs[vmName]
		if len( formVar[1] ) > 0:
			print '      <ChineseWallTypes>'
			for chw in formVar[1]:
				print '        <Type>' + chw + '</Type>'
			print '      </ChineseWallTypes>'

		print '    </VirtualMachineLabel>'

	print '  </SubjectLabels>'

def sendPLObjXml( ):
	global formResNames, allResStes

	# Resources...
	if len( formResNames[1] ) == 0:
		return

	print '  <ObjectLabels>'
	for resName in formResNames[1]:
		print '    <ResourceLabel>'
		print '      <Name>' + resName + '</Name>'
		formVar = allResStes[resName]
		if len( formVar[1] ) > 0:
			print '      <SimpleTypeEnforcementTypes>'
			for ste in formVar[1]:
				print '        <Type>' + ste + '</Type>'
			print '      </SimpleTypeEnforcementTypes>'

		print '    </ResourceLabel>'

	print '  </ObjectLabels>'


# Set up initial HTML variables
headTitle = 'Xen Policy Generation'

# Form variables
#   The format of these variables is as follows:
#   [ p0, p1, p2, p3, p4, p5 ]
#     p0 = input type
#     p1 = the current value of the variable
#     p2 = the hidden input name attribute
#     p3 = the name attribute
#     p4 = the value attribute
#     p5 = text to associate with the tag
formPolicyName    = [ 'text',
			'',
			'h_policyName',
			'i_policyName',
			'',
			'',
		    ]
formPolicyUrl     = [ 'text',
			'',
			'h_policyUrl',
			'i_policyUrl',
			'',
			'',
			]
formPolicyRef    = [ 'text',
			'',
			'h_policyRef',
			'i_policyRef',
			'',
			'',
			]
formPolicyDate    = [ 'text',
			getCurrentTime( ),
			'h_policyDate',
			'i_policyDate',
			'',
			'',
		    ]
formPolicyNSUrl   = [ 'text',
			'',
			'h_policyNSUrl',
			'i_policyNSUrl',
			'',
			'',
			]
formPolicyOrder   = [ 'radiobutton-all',
			'v_ChWall',
			'h_policyOrder',
			'i_policyOrder',
			[ 'v_Ste', 'v_ChWall' ],
			[ 'Simple Type Enforcement', 'Chinese Wall' ],
		    ]
formPolicyUpdate  = [ 'button',
			'',
			'',
			'i_PolicyUpdate',
			'Update',
			'',
		    ]

formSteTypes      = [ 'list',
			[],
			'h_steTypes',
			'i_steTypes',
			'',
			'',
		    ]
formSteDel        = [ 'button',
			'',
			'',
			'i_steDel',
			'Delete',
			'',
		    ]
formSteType       = [ 'text',
			'',
			'',
			'i_steType',
			'',
			'',
		    ]
formSteAdd        = [ 'button',
			'',
			'',
			'i_steAdd',
			'New',
			'',
		    ]

formChWallTypes   = [ 'list',
			[],
			'h_chwallTypes',
			'i_chwallTypes',
			'',
			'',
		    ]
formChWallDel     = [ 'button',
			'',
			'',
			'i_chwallDel',
			'Delete',
			'',
		    ]
formChWallType    = [ 'text',
			'',
			'',
			'i_chwallType',
			'',
			'',
		    ]
formChWallAdd     = [ 'button',
			'',
			'',
			'i_chwallAdd',
			'New',
			'',
		    ]

formCSNames       = [ '',
			[],
			'h_csNames',
			'',
			'',
			'',
		    ]
formCSName        = [ 'text',
			'',
			'',
			'i_csName',
			'',
			'',
		    ]
formCSAdd         = [ 'button',
			'',
			'',
			'i_csAdd',
			'New',
			'',
		    ]

formXmlGen          = [ 'button',
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

# This is a set of templates used for each conflict set
#   Each conflict set is initially assigned these templates,
#   then each form attribute value is changed to append
#   "_conflict-set-name" for uniqueness
templateCSDel     = [ 'button',
			'',
			'',
			'i_csDel',
			'Delete',
			'',
		    ]
allCSDel          = {};

templateCSMTypes  = [ 'list',
			[],
			'h_csmTypes',
			'i_csmTypes',
			'',
			'',
		    ]
templateCSMDel    = [ 'button',
			'',
			'',
			'i_csmDel',
			'Delete',
			'',
		    ]
templateCSMType   = [ 'list',
			[],
			'',
			'i_csmType',
			'',
			'',
		    ]
templateCSMAdd    = [ 'button',
			'',
			'',
			'i_csmAdd',
			'Add',
			'',
		    ]
allCSMTypes       = {};
allCSMDel         = {};
allCSMType        = {};
allCSMAdd         = {};

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

formResNames      = [ '',
			[],
			'h_resNames',
			'',
			'',
			'',
		    ]
formResDel        = [ 'button',
			'',
			'',
			'i_resDel',
			'Delete',
			'',
		    ]
formResName       = [ 'text',
			'',
			'',
			'i_resName',
			'',
			'',
		    ]
formResAdd        = [ 'button',
			'',
			'',
			'i_resAdd',
			'New',
			'',
		    ]

# This is a set of templates used for each resource
#   Each resource is initially assigned these templates,
#   then each form attribute value is changed to append
#   "_resource-name" for uniqueness.
templateResDel    = [ 'button',
			'',
			'',
			'i_resDel',
			'Delete',
			'',
		    ]
allResDel         = {};

templateResStes   = [ 'list',
			[],
			'h_resStes',
			'i_resStes',
			'',
			'',
		    ]
templateResSteDel = [ 'button',
			'',
			'',
			'i_resSteDel',
			'Delete',
			'',
		    ]
templateResSte    = [ 'list',
			[],
			'',
			'i_resSte',
			'',
			'',
		    ]
templateResSteAdd = [ 'button',
			'',
			'',
			'i_resSteAdd',
			'Add',
			'',
		    ]
allResStes        = {};
allResSteDel      = {};
allResSte         = {};
allResSteAdd      = {};

# A list of all form variables used for saving info across requests
formVariables     = [ formPolicyName,
			formPolicyUrl,
			formPolicyRef,
			formPolicyDate,
			formPolicyNSUrl,
			formPolicyOrder,
			formSteTypes,
			formChWallTypes,
			formCSNames,
			formVmNames,
			formVmNameDom0,
			formResNames,
		    ]

policyXml         = ''
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
		sendPolicyXml( )

if (not formData.has_key( formXmlGen[3] )) or (xmlIncomplete == 1 ):
	# Send HTML to continue processing the form
	sendHtmlHeaders( )
	sendPolicyHtml( )
