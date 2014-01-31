#! /usr/bin/python2.6
##################################################################################################################################
#Copyright 2013 Carnegie Mellon University
#
#This material is based upon work funded and supported by Department of Homeland Security under 
#Contract No. FA8721-05-C-0003 with Carnegie Mellon University for the operation of the Software Engineering Institute,
#a federally funded research and development center sponsored by the United States Department of Defense.
#
#Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) 
#and do not necessarily reflect the views of Department of Homeland Security or the United States Department of Defense.
#
#References herein to any specific commercial product, process, or service by trade name, trade mark, manufacturer, or otherwise,
#does not necessarily constitute or imply its endorsement, recommendation, or favoring by Carnegie Mellon University 
#or its Software Engineering Institute.
#
#NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS.
#CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING,
#BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
#CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK,
#OR COPYRIGHT INFRINGEMENT.
#
#This material has been approved for public release and unlimited distribution.
#
#Carnegie Mellon(R) is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.
#
#DM-0000800
##################################################################################################################################
'''
Usage:
  cif-json2stix ([(- <input> <searchParam> [<configFile>]| -f <input> <output> <searchParam> [<configFile>])] | (-m <input> <output> <searchParam> [<configFile>] [<pattern>]))
  cif-json2stix (--version)
  cif-json2stix (-h | --help)

Options:
  --version            Show version.
                           [default: 1.0]
  -h --help            Show this screen.
  -                    Take an input stream and output the result into output stream.
      <input>          Input stream of JSON formated data.
      <searchParam>    The search parameter that was used to search CIF.
      <configFile>     The full path to the configuration file with the list of handled CIF fields.
                          [default: stix_builder.cfg]
  -f                   Take file as an input and output into provided file.
      <input>          Full path and name of the input file, which should be in CIF standard JSON-like format - objects in {}, but no commas in between.
      <output>         Full path and name of the output XML file.
      <searchParam>    The search parameter that was used to search CIF.
      <configFile>     The full path to the configuration file with the list of handled CIF fields.  
                          [default: stix_builder.cfg]
  -m                   Take multiple files as an input . Output to corresponding multiple files.
      <input>          Full path to the directory, where the input files are located (same format as above).
      <output>         Full path to the directory, where the output files will be put.
      <searchParam>    The search parameter that was used to search CIF.
      <pattern>        Parse only file matching this pattern in the input directory.
                           [default: *.json]
      <configFile>     The full path to the configuration file with the list of handled CIF fields.  
                          [default: stix_builder.cfg]
'''
import datetime
import json
import glob
from docopt import docopt
import sys

'''
Created on Jun 22, 2013
@author: Nataliya A. Shevchenko
'''    
def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    '''
    testMode: if True === test, so all printouts run 
              as well as some vars set to run as independent module

    '''        
    global testMode
    testMode = True #False#True
    
    global log_string
    log_string = str(datetime.datetime.now().time()) + ": Start\n"
    
    global args
    args = docopt(__doc__, argv)
    
#FOR TESTING:START
    if testMode:
        args = {'-m':True, '<input>':'<<JSON_Files dir/>>'
                ,'<output>':'<<STIX_XML_Files dir/>>','<searchParam>':'multiple files'
                ,'<configFile>':'stix_builder.cfg'}#,'<pattern>':'*-cif.json'}
#FOR TESTING:END

    _read_config()

    _parse_command_args(args)
    
    _write_log()

    
'''
    reads the configuration file
    san: 08/20/2013 - not in use any more
'''  
def _read_config():
    import ConfigParser
    
    configFileName_default = 'stix_builder.cfg'
    if testMode:
        configFileName_default = 'stix_builder.cfg'
        
    config = ConfigParser.SafeConfigParser()
    
    if args.get('<configFile>'):
        config.read(args.get('<configFile>'))
    else:
        config.read(configFileName_default)
    
    global fieldsList
    fieldsList = json.loads(config.get("Fields","list"))
    
    global protocolsList
    protocolsList = json.loads(config.get("Protocols","list"))
    
    global jsonFilePath
    jsonFilePath = config.get("Paths and Extensions","json_path")

    global stixFilePath
    stixFilePath = config.get("Paths and Extensions","stix_path")

def _write_log():
    '''
    Write content of log_string to a log file
    '''
    logFileName = "json2stix_log_" + str(datetime.datetime.now().time()) + ".log"
    logFile = open(logFileName, "w")
    try:
        logFile.write(log_string)
    finally:
        logFile.close()
    
    
'''
    parses command line a arguments
'''
def _parse_command_args(args):
    global streamFlag
    streamFlag = False
    global myJsonStream
    myJsonStream = ""
    global myJsonFile
    myJsonFile = None
    global outputFile
    outputFile = None
    global jsonPattern
    jsonPattern = None
    global mySearchParam 
    mySearchParam = ""

    if args.get('--version'):
        print "CIF-TO-STIX Builder version 0.1"
        return "CIF-TO-STIX Builder version 0.1"
    
    if args.get('-'):
        streamFlag = True
        myJsonStream = args.get('<input>')
        mySearchParam = args.get('<searchParam>')
        
        if testMode:
            print "It runs from CIF!"
            print "myJsonStream: " + myJsonStream
            print "mySearchParam: " + mySearchParam
            
        resultXML = _export_multi_json()
        print resultXML # do not remove!!!!
        sys.stdout = resultXML
        
        return resultXML
        
    if args.get('-f'):
        mySearchParam = args.get('<searchParam>')
        outputFile = args.get('<output>')
        myJsonFile = args.get('<input>')

        if testMode:
            print " -f run mode"
            print "myJsonFile: " + myJsonFile
            print "outputFile: " + outputFile
            print "mySearchParam: " + mySearchParam
            
        _export_multi_json()
        
        
    if  args.get('-m'):
        mySearchParam = args.get('<searchParam>')
        global jsonPath
        jsonPath = args.get('<input>')
 
        if args.get('<pattern>') is None:
            jsonPattern = '*.json'
        else:
            jsonPattern = args.get('<pattern>')
        
        global stixPath
        stixPath = args.get('<output>')
        
        json_file_list = glob.glob1(jsonPath,jsonPattern)
        
        if testMode:
            print "-m run mode"
            print "jsonPath: " + jsonPath
            print "jsonPattern: " + jsonPattern
            print "stixPath: " + stixPath
            print "mySearchParam: " + mySearchParam
            print "json_file_list:"
            print json_file_list
    
        #iterate through the list and export each json to stix
        for file_name in json_file_list:
            myJsonFile = str(file_name).rsplit(".json")[0]
            #read multi-object json, create STIX, write separate xml file for each file
            _export_multi_json()        


'''
    iterate through the json objects and creates one STIX document
'''
def _export_multi_json():
    from stix.core import STIXPackage, STIXHeader
    
    if jsonPattern is None:
        if streamFlag: #stream
            fullFileName = "cifStream"
        else: 
            fullFileName = myJsonFile
            xmlFileName = outputFile
    else:
        fullFileName = jsonPath + myJsonFile + '.json'
        fileName = "stix_" + str(myJsonFile)
        xmlFileName = stixPath + fileName + '.xml'
        
    if testMode:
        print "-----------------File Name: -------- " + fullFileName
        print "xmlFileName: " + xmlFileName
        
    global log_string
    log_string = log_string + "\n\n" + str(datetime.datetime.now().time()) + ": fullFileName: " + fullFileName + "\n"
    log_string = log_string + str(datetime.datetime.now().time()) + ": xmlFileName: " + xmlFileName + "\n"

    wholeJson = _prepare_json(fullFileName)
    
    stix_package = STIXPackage()
    stix_header = STIXHeader()

    stix_header.description = "Search result from CIF with search parameter " + str(mySearchParam)
    stix_header.title = "Indicators from search by " + str(mySearchParam)

    stix_package.stix_header = stix_header
    stix_header.package_intent = "Purpose: mitigation"
    
    for x in wholeJson:
        indicatorIns = _export_from_json_to_xml(json.loads(x))
        stix_package.add_indicator(indicatorIns)
        
    if streamFlag is False:
        f = open(xmlFileName, 'w')
        try:
            f.write(stix_package.to_xml())
        finally:
            f.close()
   
    #if testMode:
    #    print stix_package.to_xml()
   
    log_string = log_string + str(datetime.datetime.now().time()) + ": -------------- STIX----------- \n\n" + stix_package.to_xml()

    return stix_package.to_xml()        
        
'''
    takes single jsom object and parse it
'''    
def _export_from_json_to_xml(json1):
    import re
    from stix.indicator.indicator import Indicator
    from cybox.core import observable
    from cybox.common import Hash
    from cybox.objects.file_object import File
   
    indicatorIns = Indicator()
    indicDesc = "Additional fields: "
    
    if testMode:
        print "------------New Indicator: Start------------"
        print "--------------check dictionary ----------------"
        if json1["relatedid_restriction"]: print json1["relatedid_restriction"]
        if json1["source"]: print json1["source"]
        if "ardig" in json1 and json1["ardig"]: print str(json1["ardig"])
        if "address" in json1 and json1["address"]:print json1["address"]
        print "--------------check dictionary:END----------------"
    
    #need to be set before setting times producer attributes
    indicatorIns.set_producer_identity("None")
    
    strAddress = ""
    strAsn = ""
    strAsnDesc = ""
    strRir = ""
    strCc = ""
    strPrefix = ""
    strRdata = ""
    strDescShort = ""
    strMalware = ""
    strProtocol = ""
    strPortList = ""
    for item in json1.keys():
        if fieldsList.get(item) is None:
            log_string = log_string + "New field: " + str(json1.get(item)) + "\n"
            
    if json1.get("whois") is not None:
        indicDesc = indicDesc + "whois = " + str(json1["whois"]) + "; "
    
    if json1.get("relatedid_restriction") is not None:
        indicDesc = indicDesc + "relatedid_restriction = " + str(json1["relatedid_restriction"]) + "; "
        
    if json1.get("source") is not None:
        indicatorIns.set_producer_identity(json1["source"])
        
    if json1.get("contact") is not None:
        indicDesc = indicDesc + "contact = " + json1["contact"] + "; "
    
    if json1.get("purpose") is not None:
        indicDesc = indicDesc + "purpose = " + str(json1["purpose"]) + "; "
    
    if json1.get("asn") is not None:
        strAsn = json1["asn"]
          
    if json1.get("asn_desc") is not None:
        strAsnDesc = json1["asn_desc"]
          
    if json1.get("rir") is not None:
        strRir = json1["rir"]
          
    if json1.get("cc") is not None:
        strCc = json1["cc"]
          
    if json1.get("rdata") is not None:
        strRdata = json1["rdata"]
          
    if json1.get("prefix") is not None:
        strPrefix = json1["prefix"]
          
    if json1.get("alternativeid") is not None:
        indicDesc = indicDesc + "alternativeid = " + str(json1["alternativeid"]) + "; "
          
    if json1.get("detecttime") is not None:
        indicatorIns.set_produced_time(json1["detecttime"])
          
    if json1.get("address") is not None:
        strAddress = json1["address"]
        
    if json1.get("alternativeid_restriction") is not None:
        indicDesc = indicDesc + "alternativeid_restriction = " + str(json1["alternativeid_restriction"]) + "; "
        
    if json1.get("id") is not None:
        indicatorIns.id_=json1["id"]
         
    if json1.get("guid") is not None:
        indicDesc = indicDesc + "guid = " + str(json1["guid"]) + "; "
         
    if json1.get("severity") is not None:
        indicDesc = indicDesc + "severity = " + str(json1["severity"]) + "; "
         
    if json1.get("assessment") is not None:
        indicDesc = "Assessment: " + str(json1["assessment"]) + ". " + indicDesc
        
    if json1.get("description") is not None:
        descList = str(json1["description"]).rsplit()
        if len(descList) > 1:
            strDescShort = descList[len(descList)-1]
        else:
            strDescShort = str(json1["description"])
        indicDesc = indicDesc + "description = " + str(json1["description"]) + "; "
        
    if json1.get("relatedid") is not None:
        indicDesc = indicDesc + "relatedid = " + str(json1["relatedid"]) + "; "
         
    if json1.get("reporttime") is not None:
        indicatorIns.set_received_time(json1["reporttime"])
        
    if json1.get("confidence") is not None:
        indicDesc = indicDesc + "confidence = " + json1["confidence"] + "; "
        
    if json1.get("restriction") is not None:
        indicDesc = indicDesc + "restriction = " + json1["restriction"] + "; "
        
    if json1.get("malware_hash") is not None:
        strMalware =json1["malware_hash"]
        
    if json1.get("protocol") is not None:
        strProtocol = str(json1["protocol"])
       
    if json1.get("portlist") is not None:
        strPortList = str(json1["portlist"])
       
    #Address    
    #build address param
    addressParam = {'strAddress':strAddress,'strDescShort':strDescShort,'strAsn':strAsn,'strAsnDesc':strAsnDesc,
                    'strRir':strRir,'strCc':strCc,'strPrefix':strPrefix,'strRdata':strRdata,
                    'strProtocol':strProtocol,'strPortList':strPortList,'indicDesc':indicDesc,}
    if testMode:
        print "Address: " + addressParam["strAddress"]
        print "strDescShort: " + addressParam["strDescShort"]
    
    if strAddress:
        #address
        indicDesc = _build_adderss_obj(addressParam,indicatorIns)
   
    #rdata onlly
    if strAddress is None and strRdata:
        matchRez = re.match("""((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}
                            (25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)""", strRdata)
        if matchRez:
            #address = helper.create_ipv4_observable(strRdata)
            indicatorIns.add_observable(observable.Observable(Address(strRdata,'ipv4-addr')))
        else:
            indicatorIns.add_observable(observable.Observable(URI(strRdata,'Domain Name')))
        
        if testMode:
            print "It's rdata only"
           
    #malware
    if strMalware:
        malFile = File()
        hash_ = Hash(strMalware)
        malFile.add_hash(hash_)
        malware = observable.Observable(malFile)
        indicatorIns.add_observable(malware)
        
        if testMode:
            print "It's malware_hash"
    
    if indicDesc:
        indicatorIns.description = indicDesc
    
    return indicatorIns

'''
    san: 08/19/2013 
    This function analyzes address field and other fields from json 
    and builds corresponding STIX object from it
'''
def _build_adderss_obj(addressParam,indicatorIns):
    import re
    from cybox.objects.address_object import Address
    from cybox.objects.uri_object import URI
    from cybox.core import observable

    thisIndicDesc = ''
    #check for IPv4
    matchRez = re.match("""((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)""", addressParam['strAddress'])
    #IPv4
    if matchRez:
        if addressParam['strDescShort'] == "ssh":
            thisIndicDesc = thisIndicDesc + _address_ssh(addressParam,indicatorIns)
            if testMode:
                print "It's ssh"
        else:
            indicatorIns.add_observable(observable.Observable(Address(addressParam['strAddress'],'ipv4-addr')))
            thisIndicDesc = thisIndicDesc + _address_ipv4(addressParam,indicatorIns)
            if testMode:
                print "It's ipv4"
            
    else:
        thisIndicDesc = addressParam['indicDesc']
        matchRez = re.match("""/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/ """, addressParam['strAddress'])
            
        #IPv6
        if matchRez:
            indicatorIns.add_observable(observable.Observable(Address(addressParam['strAddress'],'ipv6-addr')))
            if testMode:
                print "It's IPv6"
        else:
            #check for domain
            matchRez = re.match("""^[a-zA-Z0-9\-\.]+\.(com|org|net|mil|edu|COM|ORG|NET|MIL|EDU|uk|ca|ru|fr|ch|de|ua)$""", addressParam['strAddress'])
                
            #domain
            if matchRez:
                indicatorIns.add_observable(observable.Observable(URI(addressParam['strAddress'],'Domain Name')))
                if addressParam['strRdata']:
                    indicatorIns.add_observable(observable.Observable(Address(addressParam['strRdata'],'ipv4-addr')))
                    if testMode:
                        print "It's domain with rdata"
                    
                if testMode:
                    print "It's domain"
            else:
                #check for email
                matchRez = re.match("""^[a-zA-Z0-9._%-]+@[a-zA-Z0-9\-\.]+\.(com|org|net|mil|edu|COM|ORG|NET|MIL|EDU|uk|ca|ru|fr|ch|de|ua)$""",addressParam['strAddress'])
                if testMode:
                    print "matchRez: " + str(matchRez)
                #email
                if matchRez or addressParam['strDescShort'] == "email":
                    indicatorIns.add_observable(observable.Observable(Address(addressParam['strAddress'],'e-mail')))
                    
                    if testMode:
                        print "It's email"
                else:
                    #ckeck for URL
                    matchRez = re.match("""((https?)|(ftps?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)""", addressParam['strAddress'])
                    if matchRez:
                        #url
                        indicatorIns.add_observable(observable.Observable(URI(addressParam['strAddress'],'URL')))
                        if addressParam['strRdata']:
                            thisIndicDesc = thisIndicDesc + "; Reversed Data = " + addressParam['strRdata']
                        if testMode:
                            print "It's URL"
                        
    return thisIndicDesc


'''
    san: 08/19/2013 
    ----- This funciton creates address type ipv4 with additional fields object
'''
def _address_ipv4(addressParam,indicatorIns):
    from cybox.objects.address_object import Address
    from cybox.core import observable
    
    thisIndicDesc = addressParam['indicDesc']
    
#   IP address +asn,rir,cc,prefix
    if addressParam['strAsn'] and addressParam['strAsnDesc'] and addressParam['strCc'] and addressParam['strRir']:
        thisIndicDesc = thisIndicDesc + addressParam['strAsnDesc'] + "; Internet Registry = " + addressParam['strRir'] + "; Country Code = " + addressParam['strCc']
        indicatorIns.add_observable(observable.Observable(Address(addressParam['strAsn'],'asn')))
        if testMode:
             print "IP ddress +asn,rir,cc,prefix"
        #IP address + prefix
    elif addressParam['strPrefix']:
        thisIndicDesc = thisIndicDesc + "; Prefix = " + addressParam['strPrefix']
        if testMode:
            print "IP address + prefix"
            
    return thisIndicDesc


'''
    san: 08/19/2013 
    ----- This funciton creates address type ssh object
'''
def _address_ssh(addressParam,indicatorIns):
    
    from cybox.objects.address_object import Address
    from cybox.objects.uri_object import URI
    from cybox.core import observable
    from cybox import helper
    from cybox.objects.network_connection_object import NetworkConnection as Connection
    
    thisIndicDesc = addressParam['indicDesc']
    if testMode:
        print "ipV4 and ssh"
    
    tmpProto =  protocolsList.get(addressParam['strProtocol'])
    if testMode:             
        print "Protocol" + tmpProto
    
    if tmpProto is not None:
        connDict = {'layer7_protocol':addressParam['strDescShort'],'layer4_protocol':tmpProto,'source_socket_address':{'ip_address':addressParam['strAddress'],'port':{'port_value':addressParam['strPortList']}}}
    else:
        connDict = {'layer7_protocol':addressParam['strDescShort'],'layer4_protocol':'TCP','source_socket_address':{'ip_address':addressParam['strAddress'],'port':{'port_value':addressParam['strPortList']}}}
    
    indicatorIns.add_observable(observable.Observable(Connection.from_dict(connDict)))
                
    #IP address +asn,rir,cc,prefix
    if addressParam['strAsn'] and addressParam['strAsnDesc'] and addressParam['strCc'] and addressParam['strRir']:
        thisIndicDesc = thisIndicDesc + "asn_desc = " + addressParam['strAsnDesc'] + "; Internet Registry = " + addressParam['strRir'] + "; Country Code = " + addressParam['strCc']
        indicatorIns.add_observable(observable.Observable(Address(addressParam['strAsn'],'asn')))
        if testMode:
            print "it's asn"
                
    if addressParam['strRdata']:
        indicatorIns.add_observable(observable.Observable(URI(addressParam['strRdata'],'Domain Name')))
        if testMode:
            print "It's domain"
                    
    if addressParam['strPrefix']:
        thisIndicDesc = thisIndicDesc + "; Prefix = " + addressParam['strPrefix']
        if testMode:
            print "it's prefix"
            
    return thisIndicDesc

'''
    san: 08/19/2013 
    --- This function reads from bad-formed multy object json file,
        creates dictionalry of json objects
'''
def _prepare_json(fullFileName):
    
    jsonDic = []
    if streamFlag:
        init_json = myJsonStream
    else:
        init_json = open(fullFileName).read()

    descList = str(init_json).rsplit('}') 
    
    if testMode:
        print "size: "+str(len(descList)) + "; _prepare_json: " + str(descList[len(descList)-1])
        
    if len(descList) > 0:
        for k in range(len(descList)):
            if descList[k] != '':
                tmp = str(descList[k]) + "}"
                jsonDic.append(tmp)
                
    return jsonDic
  
if __name__ == "__main__": sys.exit(main())
    
