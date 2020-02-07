######
# @author:      Ana Nieto,
# @email:       nieto@lcc.uma.es
# @institution: University of Malaga
# @country:     Spain
# @website:     https://www.linkedin.com/in/ana-nieto-72b17718/
######

import hashlib
from signature import *
import exiftool as exiftool
import json
import datetime
import eml_parser
import random
import re
import ipaddress
import pprint
import itertools
import subprocess
import memory
from stegano import lsb

#-----------------------------------
# CONST - QUESTIONS
#-----------------------------------
#   EMAIL ANALYSIS
# These are generic questions for EMAIL analysis
PARSE_QUESTIONS_EMAIL = {'¿Qué dirección de correo electrónico aparece de origen?': 'SENDER',
                    '¿Cuál es la IP del Servidor de Envío?':'IP_SERVER_SENDER',
                    '¿Cuántos servidores intermedios hay (saltos)?':'NUM_INT_SERVERS',
                    'Proporciona el nombre o IP de uno de los servidores intermedios':'INT_SERVERS',
                    '¿Es phishing?':'DEF:NO',
                    '¿Es anónimo?':'DEF:NO',
                    '¿Es spoofing?':'DEF:SI'}
                    #'¿Existen indicios de algún otro ataque?':'DEF:NO',
                    #'¿Es estafa?':'DEF:NO'}

#   MEMORY ANALYSIS
PARSE_QUESTIONS_MEMORY = {
                    'Using volatility, how many processes are listed using pslist?': 'MEMORY:Q1',
                    'Using volatility, provide the PID of a (potential) hidden process. Answer NO if there is none':'MEMORY:Q2',
                    'Using volatility, provide the name of a (potential) hidden library (DLL). Answer NO if there is none':'MEMORY:Q3',
                    'Using volatility, provide the name of a (potential) hidden driver. Answer NO if there is none':'MEMORY:Q4',
                    'Using volatility, provide the IP of a remote connection. Answer NO if there is none':'MEMORY:Q5',
                    'Using volatility, are there indications of code injection?':'MEMORY:Q6',
                    'Using volatility, provide the name of a (potential) rogue process. Answer NO if there is none': 'MEMORY:Q7'}
#   DISK ANALYSIS
PARSE_QUESTIONS_DISK = {
                    'How many partitions does the disk have?':'Q1FSA',
                    'What is the file system used in the primary partition?':'Q2FSA',
                    'Is there any encrypted partition?':'Q3FSA',
                    'How many sectors do we have?':'Q4FSA',
                    'What is the entry point of the MFT?':'Q5FSA',
                    'What is the block size (sector size)?':'Q6FSA',
                    'How many sectors do we have in a cluster?':'Q7FSA'}

#-----------------------------------
# CLASSES
#-----------------------------------
class UseCase():
    """
    THIS CLASS REPRESENTS THE CONTEXT OF A USE CASE
    """
    [PATH, DISK, MEMORY, EVIDENCE, OWN, ACQUIRED_BY, EQUIPMENT, TYPE_EV, TAG, FOLDER, NAME, DESCRIPTION, QUESTIONS,
     HASH, ALGORITHM, VALUE, USB, PC] = \
        ['path', 'disk', 'memory', 'evidence', 'own', 'acquired_by', 'equipment', 'type', 'tag', 'folder', 'name',
         'description', 'questions', 'hash', 'algorithm', 'value', 'usb', 'pc']

    # ---------------------------------
    #    EXAMPLES
    # ---------------------------------
    # Training: The art of memory forensics
    MEMORY_TRAINING = {PATH: 'resources/memory/', TAG: 'tam',
                       EVIDENCE: [
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam01', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample001.bin'}}},
                    #   {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam02', FOLDER: 'tam',
                    #    EQUIPMENT: {MEMORY: {NAME: 'sample002.bin'}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample003.bin'}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample004.bin'}}},
                    #   {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                    #    EQUIPMENT: {MEMORY: {NAME: 'sample005.bin'}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample006.bin'}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample007.bin'}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample008.bin'}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'MLH,AC,JL,AW', OWN: 'anonymous', TAG: 'tam03', FOLDER: 'tam',
                        EQUIPMENT: {MEMORY: {NAME: 'sample009.bin'}}},
                   ],
                       DESCRIPTION:{NAME: 'The Art of Memory Forensics',
                                QUESTIONS: [{x:PARSE_QUESTIONS_MEMORY[x]} for x in PARSE_QUESTIONS_MEMORY]}}

    OCTOPUS_BURGUER = {PATH: 'resources/use_case/receta/', TAG: 'receta',
                       EVIDENCE:[
                           {TYPE_EV: PC, ACQUIRED_BY: 'nieto', OWN: 'bob', TAG: 'recetaDisk', FOLDER: '',
                            EQUIPMENT:{DISK:{NAME: 'DISCO4',
                                             HASH:{ALGORITHM:'sha1',
                                                   VALUE:'1b8366dba709cea57c529f3c8237e7c6d1f899ff'}}}},
                           {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'bob', TAG: 'recetaUSB', FOLDER: '',
                            EQUIPMENT:{DISK:{NAME: 'USB4',
                                             HASH:{ALGORITHM:'sha1',
                                                   VALUE:'8c0b8ab99f9aa251736f3cdc459aa5fa87596168'}}}}],
                       DESCRIPTION:{NAME: 'Receipt, She Wrote',
                                    QUESTIONS:[
                                        {'Did Bob Keep in touch with members of the RAT':'DEF:YES'},
                                        {'Are there any indications that the recipe published has been on Bob\'s PC?':'DEF:YES'},
                                        {'Are there indications that Bob has sent, in some way, the recipe?':'DEF:YES'}]}}
    TUPPER_FISH = {PATH: 'resources/use_case/fish/', TAG: 'fish',
                   EVIDENCE: [
                       {TYPE_EV: PC, ACQUIRED_BY: 'A.Nieto', OWN: 'Bob DelPozo', TAG: 'fishBob', FOLDER: 'Bob',
                        EQUIPMENT:{
                            DISK: {NAME:'DDB.dd', HASH:{ALGORITHM:'sha1', VALUE:'c26ade90a6ef5d0ad392e2d4df4e5d849c5baad'}},
                            MEMORY:{NAME: 'WIN-J6500DFDG59-20181029-095652.dmp',
                                    HASH:{ALGORITHM:'sha256',
                                          VALUE:'6ff61746a5e17426dfabdb0eaed767fb5f809353e3c699a8e3e8e5cdf6426586'}}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'A.Nieto', OWN: 'Denise Jimenez', TAG: 'fishDenise', FOLDER: 'Denise',
                        EQUIPMENT: {
                            DISK: {NAME: 'DDD.dd', HASH:{ALGORITHM: 'sha1', VALUE: '044cf84880672c8c395cbc51a1863f10fe9499c4'}},
                            MEMORY: {NAME: 'DESKTOP-1LSB20S-20181029-100040.dmp',
                                     HASH: {ALGORITHM:'sha256',
                                            VALUE:'f8c8ea6e63d891a12191b66dbc2aa5153d2092c4050dd1887fff9e516bb78b68'}}}},
                       {TYPE_EV: PC, ACQUIRED_BY: 'A.Nieto', OWN: 'Clark Ruiz', TAG: 'fishClark', FOLDER: 'Denise',
                        EQUIPMENT: {DISK: {NAME: 'DDC.dd',
                                           HASH:{ALGORITHM:'sha1', VALUE:'f50075f7ff2eb63c1426bcf00c378f3f4651c3d7'}}}},
                       {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'denise', TAG: 'fishUSB1', FOLDER: 'USB',
                        EQUIPMENT: {DISK: {NAME: 'USBEVI1'}}},
                       {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'denise', TAG: 'fishUSB2', FOLDER: 'USB',
                        EQUIPMENT: {DISK: {NAME: 'USBEVI2'}}},
                       {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'denise', TAG: 'fishUSB3', FOLDER: 'USB',
                        EQUIPMENT: {DISK: {NAME: 'USBEVI3'}}},
                       {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'denise', TAG: 'fishUSB4', FOLDER: 'USB',
                        EQUIPMENT: {DISK: {NAME: 'USBEVI4'}}},
                       {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'denise', TAG: 'fishUSB5', FOLDER: 'USB',
                        EQUIPMENT: {DISK: {NAME: 'USBEVI5'}}},
                       {TYPE_EV: USB, ACQUIRED_BY: 'nieto', OWN: 'denise', TAG: 'fishUSB6', FOLDER: 'USB',
                        EQUIPMENT: {DISK: {NAME: 'USBEVI6'}}}],
                   DESCRIPTION:{
                        NAME: 'Tupper-Fish', QUESTIONS:[]}}
    USE_CASE_LIST = {OCTOPUS_BURGUER.get(TAG):OCTOPUS_BURGUER, TUPPER_FISH.get(TAG):TUPPER_FISH}

    # ---------------------------------
    #       CONSTRUCTOR
    # ---------------------------------
    def __init__(self, usecase, fileResults='tmp/', fileName=None, fileInput=None):
        if fileInput is not None:
            usecase = self.readContextFrom(fileInput)

        if not UseCase.isUseCase(usecase):
            raise ValueError('Use Case (creation)>> Unexpected structure for Use Case, please check sintaxis')

        if fileName is None:
            self.deffilename = usecase.getName()

        self.usecase = usecase
        self.pathresults = fileResults

    # ---------------------------------
    #       STATIC METHODS
    # ---------------------------------
    @staticmethod
    def getEquipmentList():
        """
        :return: a list with the known equipment types.
        """
        return [UseCase.DISK, UseCase.MEMORY]

    @staticmethod
    def isUseCase(usecase):
        """
        Checks the structure of a use case
        :param usecase: dictionary to be checked
        :return: True if the structure is correct, False in other case
        """
        path = usecase.get(UseCase.PATH)
        evi = usecase.get(UseCase.EVIDENCE)
        tag = usecase.get(UseCase.TAG)
        desc = usecase.get(UseCase.DESCRIPTION)

        res = path is not None and evi is not None and tag is not None and desc is not None and len(evi) > 0

        if not res: return False

        # Additional checks: - Structure for evidence
        for e in evi:
            type = e.get(UseCase.TYPE_EV)
            acquired = e.get(UseCase.ACQUIRED_BY)
            own = e.get(UseCase.OWN)
            tag = e.get(UseCase.TAG)
            folder = e.get(UseCase.FOLDER)
            equipment = e.get(UseCase.EQUIPMENT)
            res = type is not None and acquired is not None and own is not None and tag is not None and \
                  folder is not None and equipment is not None
            if not res: return False

            # Additional checks:
            for eq in equipment:
                if eq not in UseCase.getEquipmentList(): return False
                item = equipment[eq]
                if item.get(UseCase.NAME) is None: return False

        # Additional checks: - Structure for description
        if desc.get(UseCase.NAME) is None: return False
        questions = desc.get(UseCase.QUESTIONS)
        if questions is None or not isinstance(questions, list): return None
        for q in questions:
            res = res and len(q) == 1

        return res

    @staticmethod
    def getExammpleUseCaseList():
        return UseCase.USE_CASE_LIST

    @staticmethod
    def getMemoryTraining():
        return UseCase.MEMORY_TRAINING

    @staticmethod
    def getMemoryTrainingList():
        return UseCase.get_UC_Evidence([UseCase.getMemoryTraining()], value=UseCase.MEMORY,
                                                                            avoid_type=[UseCase.USB], list=True)

    @staticmethod
    def getExammple_UC_SheWrote():
        return UseCase.OCTOPUS_BURGUER

    @staticmethod
    def getExammple_UC_TupperFish():
        return UseCase.TUPPER_FISH

    @staticmethod
    def getExample_UC_MemoryTraining():
        return UseCase.MEMORY_TRAINING

    # ---------------------------------
    #       METHODS TO GET GENERIC VALUES
    # ---------------------------------
    def getDict(self):
        return self.usecase

    def getFileName(self):
        return self.deffilename

    def getPathResults(self):
        return self.pathresults

    # ---------------------------------
    #       METHODS TO GET VALUES FROM THE STRUCTURE
    # ---------------------------------
    def getPath(self):
        return self.usecase.get(UseCase.PATH)

    def getTag(self):
        return self.usecase.get(UseCase.TAG)

    def getEvidenceList(self):
        return self.usecase.get(UseCase.EVIDENCE)

    def getDescription(self):
        return self.usecase.get(UseCase.DESCRIPTION)

    def getName(self):
        return self.getDescription().get(UseCase.NAME)

    def getQuestions(self, update=False, onlyStrings=False):
        """
        :param update: if True updates the questions based on the evidence stored in the use case. False by default.
        :param onlyStrings: if False (by default) returns the entire structure for questions.
        :return: list of questions.
        """
        if update: self.updateQuestionsUC()

        questions = self.getDescription().get(UseCase.QUESTIONS)

        if onlyStrings:
            questions = list(itertools.chain.from_iterable([list(x.keys()) for x in questions]))
            while UseCase.TAG in questions: questions.remove(UseCase.TAG)

        return questions

    def getParsedQuestions(self, gen=True):
        """
        :param gen: if True (by default) returns questions with tag == UseCase.GEN.
        :return: questions in a single dictionary, folling the structure of questions.
        """
        questions = self.getQuestions()
        questions_strings = self.getQuestions(onlyStrings=True)

        parsed = {}
        for q in questions:
            if gen or q.get(UseCase.TAG) is None:
                parsed.update(q)

        # Remove key for GEN:
        if gen:
            while UseCase.TAG in parsed:
                del parsed[UseCase.TAG]

        return parsed


    def isOriginalQuestion(self, question):
        """
        :param question: question (string) to be made
        :return: True if the question is specific of the USE CASE, false in other case (e.g. has been generated)
        """
        questions = self.getDescription().get(UseCase.QUESTIONS)
        for q in questions:
            if q.get(question) is not None:
                return q.get(UseCase.TAG) is None


    def getEvidence(self):
        """
        Returns all the evidence in form of paths
        """
        list_disk = self.getEvidenceDisk(avoidUSB=False)
        list_mem = self.getEvidenceMemory()

        return list_disk + list_mem


    def getEvidenceMemory(self):
        return UseCase.get_UC_Evidence([self.getDict()], value=UseCase.MEMORY, list=True)

    def getEvidenceDisk(self, avoidUSB=True):
        if avoidUSB:
            return UseCase.get_UC_Evidence([self.getDict()], value=UseCase.DISK, list=True, avoid_type=[UseCase.USB])
        else:
            return UseCase.get_UC_Evidence([self.getDict()], value=UseCase.DISK, list=True, avoid_type=[])

    def getEvidenceUSB(self):
        return UseCase.get_UC_Evidence([self.getDict()], value=UseCase.DISK, list=True, avoid_type=[UseCase.PC])

    # ---------------------------------
    #       MODIFICATION METHODS
    # ---------------------------------
    def setFileName(self, filename): # same as SERA
        self.deffilename = filename


    def addGenQuestions(self, questions):
        """
        Adds generic questions to the use case
        :param questions: question structure
        """
        new_questions = self.getQuestions(onlyStrings=False)
        questions_str = self.getQuestions(onlystrings=True) #list of questions

        for q in questions: # LIST
            question = list(q.keys())
            question = q[0]
            if question not in questions_str:
                new_questions += [{q:questions[q], UseCase.TAG:'GEN'}]

        # Update questions:
        self.usecase[UseCase.DESCRIPTION][UseCase.QUESTIONS] = new_questions

    def updateQuestionsUC(self, force=False, avoid=[]):
        """
        :param force: if True forces the update of the questions. False by default.
        :param avoid: avoid questions on specific types (e.g. memory, disk, usb)
        :return: all questions that can be made on the use case after the update
        """
        if force: self.updated = False

        if self.updated:
            return self.getDescription().get(UseCase.QUESTIONS)

        if UseCase.DISK not in avoid:
            disk = self.getEvidenceDisk(avoidUSB=False)
            if disk: self.addGenQuestions(PARSE_QUESTIONS_DISK)

        if UseCase.MEMORY not in avoid:
            memory = self.getEvidenceMemory()
            if memory: self.addGenQuestions(PARSE_QUESTIONS_MEMORY)

        self.updated = True

        return self.getQuestions()

    # ---------------------------------
    #       AUXILIAR METHODS
    # ---------------------------------
    def save(self, fileName=None): # same as SERA
        """
        Save this context into a file (json)
        :param fileName: name of the file to save this context. If None then fileName == self.getFileName()
        :return: path of the new file (if any)
        """
        if fileName is None:
            fileName = self.getFileName()

        values = self.getDict()

        # write values:
        with open('%s%s.json' % (self.getPathResults(),fileName), 'w') as outfile:
            json.dump(values, outfile)

        return self.getPathResults() + fileName

    def readContextFrom(self, filePathName=None): # same as SERA
        """
        Read JSON context from a file
        :param filePathName: path and name for the file
        :return: dict representing the context
        """
        if filePathName is None:
            filePathName = self.getCompletePathFileName() + '.json'

        with open(filePathName) as json_file:
            data = json.load(json_file)

        return data

    # ---------------------------------
    #    METHODS ON LIST OF USE CASES
    # ---------------------------------
    @staticmethod
    def get_UC_Evidence(usecase_list, value=MEMORY, avoid_type=[USB], list=True):
        """
        Returns all the values in the list of UCs structure, sorted by UC
        :param ucs: List of use cases
        :param value: if 'memory' (by default) returns the path for memories in the UC. In other case returns the values
        for 'disk'
        :param avoid_type: avoid the type of events (type_ev) in the list. By default avoid 'usb'
        :param list: if True (by default) returns all the values in the same list. If false, then returns the values
        separated by user case.
        :return: list of UC evidence
        """

        total_mem = {}
        for tag in usecase_list:
            # specific use case
            uc = usecase_list[tag]
            evi_list = uc.get(UseCase.EVIDENCE)
            path_uc = uc.get(UseCase.PATH)
            uc_mem = []
            for e in evi_list:
                if e.get(UseCase.TYPE_EV) not in avoid_type:
                    evi_set = e.get(UseCase.EQUIPMENT)
                    if evi_set is not None:
                        mem = evi_set.get(value)
                        if mem is not None:
                            folder_mem = evi_set.get(UseCase.FOLDER)
                            name_mem = mem.get(UseCase.NAME)
                            uc_mem += ['%s%s%s' % (path_uc, folder_mem, name_mem)]
            total_mem.update({tag: uc_mem})

        if list:
            total_mem = [total_mem[uc] for uc in total_mem]
            total_mem = [x for x in total_mem if x]  # remove empty list

        return total_mem

#------------------------------------------------------
#   AUXILIAR
#------------------------------------------------------
def getSubstringDelimited(str_begin, str_finish, string):
    """
    Returns a string delimited by two strings
    :param str_begin: first string that is used as delimiter
    :param str_finish: second string used as delimiter
    :param string: string to be processed
    :return: string parsed, empty string if there are no matches
    """
    pos_beg = string.find(str_begin) + len(str_begin)
    pos_end = string.find(str_finish)

    if 0 <= pos_beg < len(string) and 0 <= pos_end < len(string):
        return string[pos_beg:pos_end]
    else:
        return ''

def isIP(str):
    """
    This method is inefficient, please try to change it using regular expressions
    :param str: string to be checked
    :return: True if str is valid as IPv4 or IPv6
    """
    try:
        ipaddress.ip_address(str)
        return True
    except:
        return False

def getIPs(string):
    """
    Returns list of IPs in a string
    :param string: string to be processed
    :return: list of IPs
    """
    words = re.split('\[|\]|\)|\(|;|,| |\*| \n', string)
    #avoid duplicate values:
    words = list(dict.fromkeys(words))
    #avoid spaces:
    words = list(filter(lambda a: a != ' ', words))
    ip = []

    for w in words:
        if isIP(w): ip += [w]

    return ip

def getQuestion(questione, avoid):
    """
    Returns a question (string) to be done for analysing email.
    :param questione: structure for questions.
    :param avoid: list of questions to avoid.
    :return: string with the question to be made.
    """
    if avoid is None: avoid = []
    questions = list(questione.keys())

    finalquestions = [q for q in questions if q not in avoid]

    if len(finalquestions) > 0:
        return random.choice(finalquestions)
    else:
        return ''

def getRandomMemoryChoice():
    mem_training = UseCase.getMemoryTraining()
    path = mem_training.get(UseCase.PATH)
    mem_training = mem_training.get(UseCase.EVIDENCE)

    mem = ["%s%s/%s" % (path, x.get(UseCase.FOLDER),
                         x.get(UseCase.EQUIPMENT).get(UseCase.MEMORY).get(UseCase.NAME)) for x in mem_training]
    file = random.choice(mem)

    return file

#------------------------------------------------------
#   HASHES
#------------------------------------------------------
ALG = ['MD5', 'SHA256', 'SHA1']

def hash(file, hashtype):
    """
    Calculate the hash
    :param file: file.
    :param hashtype: hash algorithm: MD5, SHA256 or SHA1.
    :return: hash value of file.
    """

    if not os.path.isfile(file) or not isinstance(hashtype, str):
        raise ValueError('hash>> unexpected type - expected file and string for hashing algorithm')

    if hashtype.upper() == 'MD5':
        hasher = hashlib.md5()
    elif hashtype.upper() == 'SHA256':
        hasher = hashlib.sha256()
    elif hashtype.upper() == 'SHA1':
        hasher = hashlib.sha1()

    # Calculate hash for file:
    with open(file, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)

    return hasher.hexdigest()

def checkhash(file, hashchosen, hashtype, printme=False):
    """
    Check if a file has a hash.
    :param file: file to be proved.
    :param hashchosen: hash to be compared.
    :param hashtype: hash algorithm: MD5, SHA256 or SHA1.
    :param printme: print the output, False by default
    :return: True if the hashtype(file) == hash, False in other case.
    """
    if not isinstance(hashchosen, str) or not isinstance(file, str) or not isinstance(hashtype, str):
        raise ValueError('checkhash>> unexpected type for input values - expected str')

    # Calculate:
    hashfile = hash(file, hashtype)

    # Say result
    if printme: print('Input hash:%s' % hashchosen)
    if printme: print('Hash %s for %s: %s' % (hashtype, file, hashfile))

    # True if these are equal, false in other case
    return str(hashfile).upper() == hashchosen.upper()


#------------------------------------------------------
#   SIGNATURE
#------------------------------------------------------
def checksignature(file, extension, printme=False):
    """
    Checks if the file signature matches with the extension chosen
    :param file: file to be checked.
    :param extension: extension chosen.
    :return: True if type(file) == extension, the type is calculated based on the signature of the file
    :Refs: https://0x00sec.org/t/get-file-signature-with-python/931
    """
    #remove '.' from extension if exists
    if extension[0]=='.': extension = extension[1:]

    compile_sigs()
    results = check_sig(file) # [(sig, desc, offset), (sig, desc, offset), ... etc.]

    if results:
        # find longest signature, and desc for output formatting purposes
        big_sig = len(max([i[0] for i in results], key=lambda x: len(x)))
        big_desc = len(max([i[1] for i in results], key=lambda x: len(x)))

        if printme: print("\n[*] First candidate signature:\n")
        sig, desc, offset = results[0][0], results[0][1], results[0][2]
        s = ("[+] {0:<%ds} : {1:<%d} {2:<20s}" % (big_sig, big_desc)).format(sig, desc, "<- Offset: " + str(offset))
        if printme: print(s)

        return extension.upper() in desc
    else:
        print('No tmp for signatures')

    return False


#------------------------------------------------------
#   METADATA
#------------------------------------------------------

def getMeta(file):
    """
    Returns metadata of a file.
    :param file:
    :return:
    """
    if not os.path.isfile(file): return {}

    #use exiftool to get metadata:
    with exiftool.ExifTool() as et:
        metadata = et.get_metadata(file)   #_batch([file])

    if metadata is not None and len(metadata)>0:
        return metadata

    return {}


def isMetadata(meta, value, file):
    """
    Checks if a pair meta:value is included as metadata in file.
    :param meta: data.
    :param value: value.
    :param file: file.
    :return: True if the pair meta:value is included, False in other case.
    """
    metadata = getMeta(file)

    return meta in list(metadata.keys()) and metadata[meta]==value


def setMeta(file, meta, value):
    """
    Changes metadata (if meta exists) or adds a new one, meta:value
    :param file: file to be processed.
    :param meta: name of the field to be included as metadata.
    :param value: value for the field meta
    :return: file with the metadata modified/added.
    """

    if not os.path.isfile(file): return False

    # use exiftool to modify metadata:
    meta = '-%s="%s"' % (meta, value)

    with exiftool.ExifTool() as et:
        params = map(os.fsencode, ['-File:%s=%s' % (meta, value), '%s' % file])
        et.execute_json(*params)#meta, file)

    return isMetadata(meta, value, file)


#------------------------------------------------------
#   EMAIL ANALYSIS
#------------------------------------------------------
def getQuestionEmail(avoid):
    """
    Returns a question (string) to be done for analysing email.
    :param avoid: list of questions to avoid.
    :return: string with the question to be made.
    """
    return getQuestion(PARSE_QUESTIONS_EMAIL, avoid)


def json_serial(obj):
    """
    Ref: https://pypi.org/project/eml-parser/
    To show the components of the email in a beautiful way
    """
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial


def printEmailInfo(file, printjson=True):
    """
    # Ref: https://pypi.org/project/eml-parser/
    Returns information about the email (.eml)
    :param file: file with extension .eml (email saved).
    :param printjson: True (by default) prints the result
    :return: file parsed as json
    """
    # Parse email from file:
    with open(file, 'rb') as fhdl:
        raw_email = fhdl.read()

    parsed_eml = eml_parser.eml_parser.decode_email_b(raw_email)
    #parsed_eml = json.dumps(parsed_eml, default=json_serial)

    # This is the file as json
    if printjson:
        pprint.pprint(parsed_eml)

    # Returns the eml parsed:
    return parsed_eml


def getServerList(parsed_email, debug=False):
    """
    Returns the list of servers in the email parsed as json
    :param parsed_email: json with the expected structure (see printEmailInfo)
    :param debug: False (by default). If True prints the info about the servers identified
    :return: list fo servers in the .eml file
    """
    if not isinstance(parsed_email, dict):
        return []

    recv_list = parsed_email.get('header').get('received')
    res = []

    for s in recv_list:
        src = s.get('src')
        name_server = getSubstringDelimited('from', ' (', src)
        ip_server = getIPs(src)
        if debug: print('-------------\nsrc:%s\nname_server:%s\nip_server:%s\n' % (src, name_server, ip_server))

        if len(ip_server)>0:
            ip_server = ip_server[0]
        else:
            ip_server = ''

        res += [{'name':name_server, 'ip':ip_server}]

    return res

def getSourceServer(parsed_email):
    """
    :param parsed_email: json with the expected structure (see printEmailInfo)
    :return: IP and name (if any) of the source server
    """
    res = {}

    if not isinstance(parsed_email, dict):
        return []

    recv_list = parsed_email.get('header').get('received')

    info = recv_list[-1].get('src')

    ip = getIPs(info)
    if len(ip)>0:
        res.update({'ip':ip})

    name = getSubstringDelimited('from', ' (', info)

    if len(getIPs(name))==0:
        res.update({'name':name})

    return res


def answerQuestionEmail(file, q):
    """
    Returns the answer to questions on file (.eml)
    :param file: email saved with extension .eml
    :param q: operation to be made (depends on the question)
    :return: answer to the question on file (.eml)
    """
    # Question must be included in the list of questions...
    if q not in PARSE_QUESTIONS_EMAIL.keys():
        return ''

    # parse email:
    parsed_eml = printEmailInfo(file, printjson=False)

    op = PARSE_QUESTIONS_EMAIL[q]
    if op == 'SENDER': #'¿Quién envía el email?'
        return parsed_eml.get('header').get('from')

    elif op == 'IP_SERVER_SENDER': # '¿Cuál es la IP del Servidor de Envío?'
        source_server = getSourceServer(parsed_eml)
        ip =  source_server.get('ip')
        if ip is None:
            return ''
        else:
            return ip

    elif op == 'NUM_INT_SERVERS': # '¿Cuántos servidores intermedios hay (saltos)?'
        return str(len(getServerList(parsed_eml))-2)

    elif op == 'INT_SERVERS': # 'Proporciona el nombre o IP de uno de los servidores intermedios'
        server_list = getServerList(parsed_eml)
        list_names = [d.get('name') for d in server_list]
        list_ips = [d.get('ip') for d in server_list]

        values = list_names + list_ips
        #remove repeated values and spaces
        values = list(dict.fromkeys(values))
        values = list(filter(lambda a: a != ' ', values))

        #remove values for source and destination
        source_server = getSourceServer(parsed_eml)
        for s in source_server:
            if s in values: values.remove(source_server[s])

        return values

    elif 'DEF:' in op: # '¿Es phishing?': 'DEF:NO', '¿Es anónimo?': 'DEF:NO', '¿Es spoofing?': 'DEF:SI'
        return op[(op.find('DEF:')+len('DEF:')):]

    return ''



#------------------------------------------------------
#   MEMORY ANALYSIS
#------------------------------------------------------
def getQuestionMemory(avoid):
    return getQuestion(PARSE_QUESTIONS_MEMORY, avoid)

def answerQuestionMemory(pathMemory, q, profile=None):
    """
    Answer a question about a memory dump using volatility
    :param pathMemory: path to the memory file (.dump)
    :param q: question to be made (must be in PARSE_QUESTIONS_MEMORY)
    :return: answer to the question
    """

    if not os.path.isfile(pathMemory):
        raise ValueError('answerQuestionMemory>> unexpected type - expected file')

    # Question must be included in the list of questions...
    if q not in PARSE_QUESTIONS_MEMORY.keys():
        return ''

    op = PARSE_QUESTIONS_MEMORY[q]

    if op == 'MEMORY:Q1':  # 'how many process are listed using pslist?'
        res = memory.getProcesses(pathMemory)
        return str(len(res))

    elif op == 'MEMORY:Q6': #'are there indications of code injection?'
        return ''

    else:
        # Next operations can return a list
        if op == 'MEMORY:Q2': # 'provide the PID of a (potential) hidden process. Answer NO if there is none'
            res = memory.getHiddenProcesses(pathMemory, profile=profile)

        elif op == 'MEMORY:Q3': #'provide the name of a (potential) hidden library (DLL). Answer NO if there is none'
            res = memory.getHiddenLibraries(pathMemory, profile=profile)

        elif op == 'MEMORY:Q4': #'provide the name of a (potential) hidden driver. Answer NO if there is none'
            res = memory.getHiddenDrivers(pathMemory, profile=profile)

        elif op == 'MEMORY:Q5': #'provide the IP of a remote connection. Answer NO if there is none'
            res = memory.getRemoteConnections(pathMemory, profile=profile)

        elif op == 'MEMORY:Q7': #'Provide the Name of a potential rogue process. Answer NO if there is none'
            res = memory.getPotentialRogueProcesses(pathMemory, profile=profile)

        elif op == 'MEMORY:Q8': #'Provide the memory profile'
            res = memory.getProfile(pathMemory)

        if len(res) == 0:
            return 'NO'

        results = [x[1] for x in res]

        if len(results) == 0 or results is None:
            results = ''

        return results

def checkAllQuestionsMemory(pathMemory):
    """
    Checks all predefined questions in a memory
    :return: string with all the answers to the questions
    """
    # Get questions:


    return 0

#------------------------------------------------------
#   DISK ANALYSIS
#------------------------------------------------------
def getQuestionMemory(avoid):
    return getQuestion(PARSE_QUESTIONS_MEMORY, avoid)


# ------------------------------------------------------
#   USE CASE ANALYSIS
# ------------------------------------------------------
def getQuestionUC(usecase, avoid):
    """
    :param usecase: Specific use case following the structure of UseCase detailed in seraforensics.py
    :param avoid: list of questions to be avoided
    :return: all questions that can be made on the use case based on the evidence stored
    """

    if not isinstance(usecase, UseCase) and UseCase.isUseCase(usecase):
        usecase = UseCase(usecase)
    else:
        raise ValueError('getQuestionUC>> Unexpected usecase value')

    questions = usecase.getParsedQuestions(gen=False)
    q = getQuestion(questions, avoid)

    if len(q) == 0:
        questions = usecase.getParsedQuestions(gen=True)
        return getQuestion(questions, avoid)


def answerQuestionUC(usecase, q):
    """
    :param usecase: use case to be analysed
    :param q: question to be done
    :return: answer to the question in the context of the use case
    """
    if not isinstance(usecase, UseCase) and UseCase.isUseCase(usecase):
        usecase = UseCase(usecase)
    else:
        raise ValueError('getQuestionUC>> Unexpected usecase value')

    questions = usecase.getQuestions(update=True)

    # Question must be included in the list of questions for the use case
    if q not in questions:
        return ''

    return 'to be defined'


