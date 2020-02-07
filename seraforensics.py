#!/usr/bin/env python3
######
# @author:      Ana Nieto,
# @email:       nieto@lcc.uma.es
# @institution: University of Malaga
# @country:     Spain
# @website:     https://www.linkedin.com/in/ana-nieto-72b17718/
######

import genera as gd
import forense as fo
import random
import warnings
import re
import os
import sys
from argparse import ArgumentParser
import json
from stegano import lsb


#-----------------------------------
# CLASSES
#-----------------------------------
class SERA():
    """
    THIS CLASS REPRESENTS THE CONTEXT OF THE SERA SYSTEM
    """
    PICTURE = ['cebra.png', 'pinguino.png', 'leon.png', 'hipo.png', 'girafa.png', 'william.png']
    FILETYPE = ['.docx', '.xlsx', '.gif', '.jpg', '.tiff', '.png']

    ACT_VAL = ['title', 'code', 'description', 'evaluation']
    STU_VAL = ['name', 'email']
    SYS_VAL = ['path_results', 'path_images', 'path_code', 'path_submissions']

    # ---------------------------------
    #       CONSTRUCTOR
    # ---------------------------------
    def __init__(self, infoactivity, infostudent, infosystem, fileInput=None):

        if fileInput is not None:
            data = self.readContextFrom(fileInput)
            infosystem = data.get('system')
            infoactivity = data.get('activity')
            infostudent = data.get('student')

        self.infoactivity = infoactivity
        self.infostudent = infostudent
        self.infosystem = infosystem


        if not self.checkMinValues():
            str_warning = 'init>> SERA created with incomplete information.\nActivity:%s\nStudent:%s\nSystem:%s' %\
                          (self.infoactivity, self.infostudent, self.infosystem)
            warnings.warn(str_warning)

        self.deffilename = '%s_%s' % (self.getStudentName().replace(' ', ''), self.getCode())


    def checkMinValues(self):
        rx = re.compile('|'.join(list(self.infoactivity.keys()) + list(self.infostudent.keys()) +
                                 list(self.infosystem.keys())))

        min_keys = SERA.ACT_VAL + SERA.STU_VAL + SERA.SYS_VAL

        for i in min_keys:
            if not rx.match(i): return False

        return True

    # ---------------------------------
    #       STATIC METHODS
    # ---------------------------------
    @staticmethod
    def getFileType():
        return SERA.FILETYPE

    @staticmethod
    def getFileTypeNumber(num):
        if 0<= num <= len(SERA.FILETYPE):
            return SERA.FILETYPE[num]
        else:
            raise ValueError('SERA class>> Unexpected number for FILETYPE array')

    # ---------------------------------
    #       METHODS TO GET THE VALUES
    # ---------------------------------
    def getFileName(self):
        return self.deffilename

    def getCompletePathFileName(self):
        return self.getPathResults() + self.getFileName()

    def getTitle(self):
        return self.infoactivity.get('title')

    def getDescription(self):
        return self.infoactivity.get('description')

    def getCode(self):
        return self.infoactivity.get('code')

    def getEvaluation(self):
        return self.infoactivity.get('evaluation')

    def getStudentName(self):
        return self.infostudent.get('name')

    def getStudentEmail(self):
        return self.infostudent.get('email')

    def getPathResults(self):
        return self.infosystem.get('path_results')

    def getPathImages(self):
        return self.infosystem.get('path_images')

    def getPathSubmissions(self):
        return self.infosystem.get('path_submission')

    def getPathCode(self):
        return self.infosystem.get('path_code')

    def getSurpisePicturePath(self):
        return self.getPathImages() + '/' + random.choice(SERA.PICTURE)

    def isPicture(self, ext):
        rx = re.compile('|'.join(['.gif', '.jpg', '.tiff', '.png']))

        return rx.match(ext)

    def getFile(self, fileExt=None):
        """
        Returns a file generated based on the information available.
        :param fileExt: if None (default) the type of file is random.
        :return: the path (string) to the new file.
        """
        if fileExt is None:
            fileExt = random.choice(SERA.FILETYPE)

        if self.isPicture(fileExt):
            gd.giveMePicture(self.getTitle(), self.getStudentName(), self.getCompletePathFileName(), fileExt,
                             evaluation=self.getEvaluation())

        elif fileExt=='.docx':
            gd.giveMeADocx(self.getTitle(), self.getStudentName(), self.getDescription(),
                                  self.getCompletePathFileName() + '.docx', evaluation=self.getEvaluation(),
                                    picture=self.getSurpisePicturePath())
        elif fileExt=='.xlsx':
            gd.giveMeAXlsx(self.getTitle(), self.getStudentName(), self.getDescription(),
                                  self.getCompletePathFileName() + '.xlsx', evaluation=self.getEvaluation(),
                                    picture=self.getSurpisePicturePath())
        else:
            return None

        return self.getCompletePathFileName() + fileExt

    def getHelloStudent(self, extension):
        if extension=='.py':
            return gd.giveMeHelloFile(self.getStudentName(), self.getFileName(), '.py', path=self.getPathCode())
        elif extension=='.cpp':
            return gd.giveMeHelloFile(self.getStudentName(), self.getFileName(), '.cpp', '.exe', path=self.getPathCode())
        else:
            return False

    def getStegoPath(self):
        return self.getPathImages() + self.getFileName() + '_stego.png'

    def getStegoImage(self, text=None):
        image = self.getSurpisePicturePath()
        if text is None:
            #Random!
            basetext = "Un %s me dijo que sin %s no hay %s, pues depende de para qué. Esto es aleatorio. " \
                       "Indica en el formulario esta palabra: %s"
            r1 = random.choice(['periquito', 'babyshark', 'buho', 'chorlito', 'alumno', 'listo', 'iluminado',
                                'apostol', 'tartamudo', 'algo'])
            r2 = random.choice(['timidez', 'aventura', 'fuerza', 'sacrificio'])
            r3 = random.choice(['recompensa', 'exito', 'fracaso', 'caida', 'altura'])
            r4 = random.choice(['ALEGRIA', 'TRISTEZA', 'VENGANZA', 'LOCURA', 'PASION'])
            text = basetext % (r1, r2, r3, r4)

        secret = lsb.hide(image, text)
        pathstego = self.getStegoPath()
        secret.save(pathstego)

        return pathstego

    def getStegoMessage(self):
        """
        :return: secret message saved in the picture.
        """
        clear_message = lsb.reveal(self.getStegoPath())

        return clear_message

    def getDict(self):
        """
        :return: this object expressed as dictionary.
        """
        return {"activity":self.infoactivity, "student":self.infostudent, "system":self.infosystem}


    def sendEmail(self, username, password, sender, sender_name, subject, file=None, smtp_server="mail.smtp2go.com", port="587"):
        """
        Sends SERA email to this user.
        :param username: username used to send emails using the smtp server (if required).
        :param password: password to be used for the username (if required).
        :param sender: emisor of this email.
        :param sender_name: name of the sender.
        :param subject: subject of the email.
        :param file: htlm file to be sent in the body.
        :return: true if the email was sent.
        """

        recipients = self.getStudentEmail()

        if file is None:
            file = gd.generaHTLM_email(self.getPathImages() + "fakehtmlemail.html",
                                       self.getPathResults() + self.getFileName() + ".html",
                                       "Student", self.getStudentName())

        if smtp_server=="mail.smtp2go.com":
            spoofstring = "--host %s --port %s --username %s --password %s  --sender %s --name \"%s\" --recipients %s " \
                      "--subject \"%s\" --filename %s" % (
                          smtp_server, port, username, password, sender, sender_name, recipients, subject, file)
            cmd = "test/email-spoofer-py/spoof.py %s" % spoofstring
            os.system(cmd)
            return True

        return False

    # ---------------------------------
    #       MODIFICATION METHODS
    # ---------------------------------
    def setFileName(self, filename):
        self.deffilename = filename

    def save(self, fileName=None):
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

    def readContextFrom(self, filePathName=None):
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
    #       REDEFINED METHODS
    # ---------------------------------
    def __str__(self):
        str = 'Title:%s\n' \
              'Code:%s\n' \
              'Description:%s\n' \
              'Evaluation:%s\n'\
              'Student:%s, %s' % \
              (self.getTitle(), self.getCode(), self.getDescription(), self.getEvaluation(), self.getStudentName(),
               self.getStudentEmail())
        return str

#-----------------------------------
# AUXILIAR METHODS
#-----------------------------------
def changeFileExtension(file):
    """
    Change the extension of a file
    :param file: file to work with.
    :return: New complete name of the file.
    """
    new_extension = random.choice(SERA.FILETYPE)
    pre, ext = os.path.splitext(file)
    newname = pre + new_extension
    os.rename(file, newname)

    return newname


def checkhash():
    a2 = input('Select file:')
    if not os.path.isfile(a2):
        print('File not found')
        return False
    a3 = True
    while a3:
        print("""
            Choose algorithm:
            [1] md5
            [2] sha256
            [3] sha1
            [*] Back to menu (different value)
            """)
        a3 = input("Your answer is: ")
        a3 = int(a3)
        if 1 <= a3 <= 3:
            values = ['md5', 'sha256', 'sha1']
            alg = values[a3-1]
            a4 = input('Provide hash value:')
            if (fo.checkhash(a2, a4, alg)):
                print('Well done!!')
                a3 = False
            else:
                print('Different values, please try again')

def checksignature():
    a2 = input('Select file:')
    if not os.path.isfile(a2):
        print('File not found')
        return False
    a3 = True
    while a3: # same order as SERA.FILETYPE
        print("""
            Choose type of file:
            [1] Microsoft Word (.docx) 
            [2] Microsoft Excel (.xlsx)
            [3] Gif (.gif)
            [4] JPEG (.jpg)
            [5] TIFF (.tiff)
            [6] PNG (.png)
            [*] Back to menu (different value)
            """)
        a3 = input("Your answer is: ")
        a3 = int(a3)
        if 1 <= a3 <= 6:
            chosen = SERA.getFileTypeNumber(a3-1)
            if a3 == 4: chosen ='JPEG'
            if (fo.checksignature(a2, chosen)):
                print('Well done!!')
                a3 = False
            else:
                print('Different values, please try again')
        else:
            a3=False

def checkmetadata(option, sample):
    if not isinstance(sample, SERA):
        print('Select a context first please (options 1 or 2)')
        return False

    if option == 'METACHALL1': #"Chooses a metadata and ask for its value to the user"
        file = sample.getFile(None)

        # Get metadata
        res = fo.getMeta(file)

        if res:
            # Propose a random challenge:
            metafields = list(res.keys())
            mf = random.choice(metafields)

            ans = 'Y'
            while ans != 'E':
                print('What is the value for the metadata field "%s" in the file %s? (Write \'E\' for exit)' % (mf, file))
                ans = input('Your answer: ')

                if res[mf] == ans:
                    print('Correct!!')
                    return True

                else:
                    print('Upps try again...')
                    ans = True

    elif option == 'METACHALL2': #"Request the user to change the metadata of the file"
        # Generate empty file:
        file = sample.getFile(None)

        # Propose the challenge:
        meta = sera.getStudentName().replace(' ', '')
        value = fo.hash(file,'md5')
        print('Include the the metadata %s:%s in the file: %s' % (meta, value, file))

        ans = 'k'
        while ans not in ['Y', 'E']:
            ans = input("Say 'Y' when you finish, 'E' to return the main manu: ")

            if ans == 'Y':
                # Check metadata
                if fo.isMetadata(meta, value, file):
                    print('This is correct!!')
                    return True
                else:
                    print('Try again...')
    return False


def useCaseAnalysis():
    a3 = True
    while a3:
        print("""
                Choose:
                [1] Select random use case
                [2] Receipt, She Wrote
                [3] Tupper-Fish
                [*] Back to menu (different value)
                """)
        a3 = input("Your answer is: ")
        a3 = int(a3)
        tags = ['receta', 'fish']
        if 1 <= a3 <= 3:
            if a3 == 1:
                t = random.choice(tags)
            else:
                t = tags[a3-2]

            chosen = fo.UseCase(fo.UseCase.getExammpleUseCaseList().get(t))
            print('Use case chosen:%s' % chosen.getName())

            # Update questions for Use Case:
            total_questions = chosen.updateQuestionsUC()

            # Ask questions:
            asked = []
            total = len(total_questions)
            correct = 0
            while ans.upper() != 'E' and (len(asked) < total):
                print("** Preparing random question (E to return the main menu) **")
                q = chosen.getQuestionUC(chosen, asked, avoidGen=False)

                if len(q) > 0:
                    print("Question: %s" % q)
                    ans = input(">")

                    # Validate question:
                    ans_system = fo.answerQuestionUC(chosen, q)
                    if isinstance(ans_system, list):
                        rx = re.compile('|'.join(ans_system))
                        if rx.match(ans):
                            print('Correct!!')
                            correct += 1

                    elif isinstance(ans_system, str) and (ans.upper() == ans_system.upper()):
                        print('Correct!!')
                        correct += 1
                    else:
                        print('The correct answer is: %s' % ans_system)

                    asked = asked + [q]

            if ans.upper() != 'E':
                print('Congrats!! No more questions!!')
            print("Results: \nNumber of questions:%s\nNumber of correct answers:%s\nPoints (over 10):%s" %
                  (total, correct, (correct * 10) / total))


        else:
            a3=False

#-----------------------------------
# TESTING METHODS
#-----------------------------------
def getInfoSamples():
    # --- Parameters received from the system:
    # Information about the Activity:
    infoactivity = {"title":"SERA-Signature", "code":"SERAIF",
                    "description":"Calcula la signatura para comprobar si corresponde con la extensión",
                    "evaluation": "+1 if the signature is correct"}

    # Information about the Student:
    infostudent = {"name":"Ana Nieto", "email":"nieto@lcc.uma.es"}

    # Information about the System:
    infosystem = {"path_results":"tmp/",
                   "path_images":"resources/picture",
                   "path_code":"resources/code"}

    return SERA(infoactivity, infostudent, infosystem)


def runSamples():
    sample = getInfoSamples()

    SERAact = sample.getTitle()
    SERAdesc = sample.getDescription()
    eval = sample.getEvaluation()
    student = sample.getStudentName()
    filename = sample.getCompletePathFileName()

    gd.giveMeADocx(SERAact, student, SERAdesc, filename + '.docx', evaluation=eval, picture=sample.getSurpisePicturePath())
    gd.giveMeAXlsx(SERAact, student, SERAdesc, filename + '.xlsx', evaluation=eval, picture=sample.getSurpisePicturePath())

    gd.giveMeHelloFile(student, filename, '.py')

    gd.giveMeHelloFile(student, filename, '.cpp', '.exe')

    gd.giveMePicture(SERAact, student, filename, '.png', evaluation=eval)
    gd.giveMePicture(SERAact, student, filename, '.jpg', evaluation=eval)
    gd.giveMePicture(SERAact, student, filename, '.gif', evaluation=eval)

    return sample

#-----------------------------------
# MAIN METHOD
#-----------------------------------
def main_options():
    sample = None
    ans = True
    while ans:
        print("""
        Choose the action:
        [1]  Run sample 
        [2]  Read context from json file
        [3]  Show context
        [4]  Generate random file 
        [5]  Generate random file and change the extension randomly
        [6]  Delete current context
        [7]  Check hash
        [8]  Check signature
        [9]  Analyse metadata
        [10] Check metadata
        [11] Check secret
        [12] Analyse email
        [13] File System analysis
        [14] Memory analysis
        [15] Use case analysis
        [16] Exit
        """)

        ans = input("Your answer is: ")
        if ans=='1': #[1]  Run sample
            if sample is None:
                sample = runSamples()
            else:
                a2 = input('This option deletes the current context and generates a new one. Are you sure?[Y/N]')
                if a2.upper()=='Y': sample = runSamples()
            if sample: print('Files created in %s' % sample.getPathResults())

        elif ans=='2': #[2]  Read files to generate context
            fileName = input('Your file:')
            if not os.path.isfile(fileName):
                print('Please, provide a file')
            else:
                sample = SERA(None, None, None, fileName)
                if sample is not None:
                    print('Context loaded from file %s' % fileName)

        elif ans=='3': #[3]  Show context
            if sample is not None:
                print(sample)
            else:
                print('Select a context first please (options 1 or 2)')

        elif ans == '4': #[4]  Generate random file
            if isinstance(sample, SERA):
                # Get random file
                location = sample.getFile(None)
                if location is not None:
                    print('File generated in:'+location)
                else:
                    print('File not created, please check the context (3)')
            else:
                print('Select a context first please (options 1 or 2)')

        elif ans=='5': #[5]  Generate random file and change the extension randomly
            if isinstance(sample, SERA):
                # Get random file
                location = sample.getFile(None)
                if location:
                    print('File generated in:' + location)
                    # Change the file extension
                    newlocation = changeFileExtension(location)
                    print('File changed:' + newlocation)
                else:
                    print('File not created, please check the context (3)')
            else:
                print('Select a context first please (options 1 or 2)')

        elif ans == '6': #[6]  Delete current context
            a2 = input('This option deletes the current context. Are you sure?[Y/N]')
            if a2=='Y':
                sample = None
                print('Context deleted')

        elif ans=='7': #[8]  Check hash
            checkhash()

        elif ans=='8': #[9]  Check signature
            checksignature()

        elif ans=='9': #[10] Analyse metadata
            if isinstance(sample, SERA):
                checkmetadata('METACHALL1', sample)
            else:
                print('Select a context first please (options 1 or 2)')

        elif ans == '10':  # [11] Check metadata
            if isinstance(sample, SERA):
                checkmetadata('METACHALL2', sample)
            else:
                print('Select a context first please (options 1 or 2)')

        elif ans=='11': #[12] Check secret
            None

        elif ans=='12': #[13] Analyse email
            if isinstance(sample, SERA):
                # Send email:
                #sample.sendEmail(username, password, "ejemplo@sera.com", "Ana Nieto", "SERA notification")
                # Wait for the student to copy the email:
                #file = input('Please, 1. save the email received, 2. copy it to the folder and 3. provide the '
                #             'path to the file:')
                file = input('Path to the .eml file (email saved): ')
                # Ask questions:
                asked = []
                total = len(fo.PARSE_QUESTIONS_EMAIL.values())
                correct = 0
                while ans.upper()!='E' and (len(asked) <  total):
                    print("** Preparing random question (E to return the main menu) **")
                    q = fo.getQuestionEmail(asked)

                    if len(q) > 0:
                        print("Question: %s" % q)
                        ans = input(">")

                        # Validate question:
                        ans_system = fo.answerQuestionEmail(file, q)
                        if isinstance(ans_system, list):
                            rx = re.compile('|'.join(ans_system))
                            if rx.match(ans):
                                print('Correct!!')
                                correct +=1

                        elif isinstance(ans_system, str) and (ans.upper() == ans_system.upper()):
                            print('Correct!!')
                            correct += 1
                        else:
                            print('The correct answer is: %s' % ans_system)

                        asked = asked + [q]

                if ans.upper()!='E':
                    print('Congrats!! No more questions!!')
                print("Results: \nNumber of questions:%s\nNumber of correct answers:%s\nPoints (over 10):%s" %
                      (total, correct, (correct*10)/total))


            else:
                print('Select a context first please (options 1 or 2)')

        # elif ans == '13': # File System analysis
        elif ans == '14': # Memory analysis
            if isinstance(sample, SERA):
                print('Select one of the following options:\n' +
                         '   [1] Choose the path for the memory to analyse\n'
                         '   [*] Any other value to assign random memory ')
                ans = input('Your answer:')
                if ans == 1:
                    file = input('Please, provide the name of the file: ')
                    if not os.path.isfile(file):
                        print('Impossible load the file, your file will be chosen randomly...')
                        file = fo.getRandomMemoryChoice()
                else:
                    file = fo.getRandomMemoryChoice()
                print('This is your memory file: %s' % file)

                # Ask questions:
                asked = []
                total = len(fo.PARSE_QUESTIONS_MEMORY.values())
                correct = 0
                while ans.upper() != 'E' and (len(asked) < total):
                    print("** Preparing random question (E to return the main menu) **")
                    q = fo.getQuestionMemory(asked)

                    if len(q) > 0:
                        print("Question: %s" % q)
                        ans = input(">")

                        # Validate question:
                        ans_system = fo.answerQuestionMemory(file, q)
                        if isinstance(ans_system, list):
                            rx = re.compile('|'.join(ans_system))
                            if rx.match(ans):
                                print('Correct!!')
                                correct += 1

                        elif isinstance(ans_system, str) and (ans.upper() == ans_system.upper()):
                            print('Correct!!')
                            correct += 1
                        else:
                            print('The correct answer is: %s' % ans_system)

                        asked = asked + [q]

                if ans.upper() != 'E':
                    print('Congrats!! No more questions!!')
                print("Results: \nNumber of questions:%s\nNumber of correct answers:%s\nPoints (over 10):%s" %
                      (total, correct, (correct * 10) / total))


            else:
                print('Select a context first please (options 1 or 2)')


        elif ans == '15':  # Use case analysis
            useCaseAnalysis()

        elif ans=='16': #Exit
            ans = False

        else:
            print('\n Not valid choice, please try again')

    print('\nBye!!')


if __name__ == "__main__":
    # Generation options
    [GEN_FILE, GEN_CHANGE_EXT, GEN_HASHALG, GEN_METACHALL1, GEN_METACHALL2, GEN_SPOOF_ARGS, GEN_MEM, GEN_UC] = \
        ['GENERA', 'GENERAEXT', 'HASHALG', 'METACHALL1', 'METACHALL2','SPOOF_ARGS', 'GEN-MEM', 'GEN-UC']

    # Checking options
    [CHECK_HASH, CHECK_SIGNATURE, CHECK_METAVALUE, CHECK_METADATA, CHECK_EMAILANALISIS, CHECK_MEMORY, CHECK_UC] = \
        ['CHECK-HASH', 'CHECK-SIGNATURE', 'METAVALUE', 'METADATA', 'EMAILANALISIS', 'CHECK-MEMORY', 'CHECK-UC']

    if (len(sys.argv)==1):
        main_options()
        exit()

    inputs = json.loads(sys.argv[1])
    opinfo = inputs.get('op')
    op = opinfo.get('op')
    activity = inputs.get('activity')
    student = inputs.get('student')
    system = inputs.get('system')

    if op.upper() == GEN_FILE:
        sample = SERA(activity, student, system)
        location = sample.getFile(None)
        if location:
            print(location,end='')

    elif op.upper() == GEN_CHANGE_EXT:
        sample = SERA(activity, student, system)
        location = sample.getFile(None)
        if location:
            # print('File generated in:' + location)
            # Change the file extension
            newlocation = changeFileExtension(location)
            print(newlocation,end='')

        else:
            print('Error, no file',end='')
            #print('File not created, please check the context (3)')

    elif op.upper() == GEN_HASHALG:
        alg = random.choice(fo.ALG)
        print(alg, end='')

    elif op.upper() == GEN_METACHALL1:#"Returns a metadata to be checked"
        file = opinfo.get('file')

        if not os.path.isfile(file):
            print('', end='')#Error, no file',end='')

        sera = SERA(activity, student, system)

        # Propose a random challenge:
        res = fo.getMeta(file)
        metafields = list(res.keys())
        mf = random.choice(metafields)

        if res:
            print(mf,end='')
        else:
            print('')

    elif op.upper() == GEN_METACHALL2:#"Returns metadata to be included"
        file = opinfo.get('file')

        if not os.path.isfile(file):
            print('')

        print(student,end='')

    elif op.upper() == GEN_SPOOF_ARGS: # Sends a string with the arguments to send a fake mail using
        # python3 spoof.py cli
        sample = SERA(activity, student, system)
        smtp_server = "mail.smtp2go.com"
        port = "587"
        username = opinfo.get('username')
        password = opinfo.get('password')
        sender= gd.getFakeEmail() # Fake email to be used #"serasystem@fakemail.com"
        sender_name = "Sera SYSTEM"
        recipients = sample.getStudentEmail()
        subject = "Este es un mensaje de SERA system"

        file = gd.generaHTLM_email(sample.getPathImages() + "fakehtmlemail.html",
                                    sample.getPathResults() + sample.getFileName()+".html",
                                    "Student", sample.getStudentName())
        spoofstring = "--host %s --port %s --username %s --password %s  --sender %s --name \"%s\" --recipients %s " \
                      "--subject \"%s\" --filename %s" % (smtp_server, port, username, password, sender, sender_name,
                                                          recipients, subject, file)

        print(spoofstring, end='')


    elif op.upper() == GEN_MEM: # Sends a string with the name of a memory dump to be used
        #mem = fo.UseCase.get_UC_Evidence(fo.UseCase.getMemoryTraining(), value=fo.UseCase.MEMORY, list=True)
        cho = fo.getRandomMemoryChoice()
        print(cho, end='')

    elif op.upper() == GEN_UC:
        a=1


    elif op.upper()== CHECK_SIGNATURE:
        file = opinfo.get('file')
        chosen = opinfo.get('chosen')

        if not os.path.isfile(file):
            print("[{text:'Error, no file found'}]", end='')

        elif not fo.checksignature(file, SERA.getFileTypeNumber(int(chosen)-1)):
            print("[{text:'Try again. Open the file with the chosen Hex Editor and check the first bytes'}]", end='')
        else:
            print('', end='')

    elif op.upper() == CHECK_HASH:
        file = opinfo.get('file')
        chosen = opinfo.get('chosen')
        hashtype = opinfo.get('hash')

        if not os.path.isfile(file):
            print('Error, invalid file',end='')
        elif not fo.checkhash(file, chosen, hashtype):
            print('You must calculate the hash of the file using the algorithm', end='')

    elif op.upper() == CHECK_METAVALUE:
        "Checks a value for a metadata"
        file = opinfo.get('file')
        metadata = opinfo.get('metadata')
        value = opinfo.get('chosen')

        metafile = fo.getMeta(file)

        if not os.path.isfile(file) or not isinstance(metafile, dict):
            print("[{text:'Error, no file found'}]", end='')

        elif str(metafile.get(metadata)) != value:
            print("[{text:'Check the metadata using the applications recommended in class'}]", end='')

        else:
            print('',end='')

    elif op.upper() == CHECK_METADATA:#"Checks if the metadata exists in a document"
        file = opinfo.get('file')
        metachallenge = opinfo.get('metadata')

        if not os.path.isfile(file) or not isinstance(metachallenge, str):
            print("[{text:'Error, no file found'}]", end='')

        # metadata included in the file:
        metafile = fo.getMeta(file)

        # metadata to be checked:
        metadata = json.loads(metachallenge)

        included = [k for k in metadata if k in list(metafile.keys()) and metafile.get(k) == metadata.get(k)]

        if len(included)==len(metadata):
            print('', end='') #Correcto
        else:
            print("[{text:'Please, check that the metadata has been added using the applications recommended in class'}]", end='')


    elif op.upper()== CHECK_EMAILANALISIS: # perform questions about an email previously sended.
        opkeys = list(opinfo.keys())

        if "answerto" in opkeys:
            # check the answers to the questions
            answers = opinfo.get("answerto")
            file = opinfo.get("file")

            total = len(answers)
            correct = 0
            for q in answers:
                ans = answers[q]
                # Validate question:
                ans_system = fo.answerQuestionEmail(file, q)
                if isinstance(ans_system, list):
                    rx = re.compile('|'.join(ans_system))
                    if rx.match(ans):
                        correct += 1

                elif isinstance(ans_system, str) and (ans.upper() == ans_system.upper()):
                    correct += 1
            if correct < total:
                sentence = 'Please review your answers.\nNumber of questions:%s, Correct:%s. ' \
                           'Points(over 10):%s' % (total, correct, (correct*10)/total)
                print("[{text:'%s'}]" % sentence, end='')


        else:
            # provide question
            avoid = opinfo.get("avoid")
            question = fo.getQuestionEmail(avoid)
            print(question, end='')

    elif op.upper() == CHECK_MEMORY: # perform questions about memory previously chosen
        opkeys = list(opinfo.keys())

        if "answerto" in opkeys:
            # check the answers to the questions
            answers = opinfo.get("answerto")
            file = opinfo.get("file")

            total = len(answers)
            correct = 0
            for q in answers:
                ans = answers[q]
                # Validate question:
                ans_system = fo.answerQuestionMemory(file, q)
                if isinstance(ans_system, list):
                    rx = re.compile('|'.join(ans_system))
                    if rx.match(ans):
                        correct += 1

                elif isinstance(ans_system, str) and (ans.upper() == ans_system.upper()):
                    correct += 1
            if correct < total:
                sentence = 'Please review your answers.\nNumber of questions:%s, Correct:%s. ' \
                           'Points(over 10):%s' % (total, correct, (correct*10)/total)
                print("[{text:'%s'}]" % sentence, end='')


        else:
            # provide question
            avoid = opinfo.get("avoid")
            question = fo.getQuestionMemory(avoid)
            print(question, end='')

    else:
        print('')
        #print('error')

    #Send back data
    sys.stdout.flush()


