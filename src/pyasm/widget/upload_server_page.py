###########################################################
#
# Copyright (c) 2005, Southpaw Technology
#                     All Rights Reserved
#
# PROPRIETARY INFORMATION.  This software is proprietary to
# Southpaw Technology, and is not to be reproduced, transmitted,
# or disclosed in any way without written permission.
#
#
#

__all__ = ['UploadServerWdg']


import os, string, sys

from pyasm.common import Environment, TacticException, Common
from pyasm.biz import File
from pyasm.search import SearchType
from pyasm.web import *
from pyasm.command import FileUpload

import shutil, re

import six
basestring = six.string_types


class UploadServerWdg(Widget):

    def get_display(self):
        web = WebContainer.get_web()

        num_files = web.get_form_value("num_files")
        files = []

        # HTML5 upload
        if num_files:
            num_files = int(num_files)
            files = []
            for i in range(0, num_files):
                field_storage = web.get_form_value("file%s" % i)
                if not field_storage or isinstance(field_storage, basestring):
                    continue

                file_name = web.get_form_value("file_name%s"% i)
                file_path = web.get_form_value("file_path%s" % i)

                if file_path:
                    file_name = file_path
                    file_name = file_path.lstrip("/")

                if not file_name:
                    file_name = self.get_file_name(field_storage)
                items = self.dump(field_storage, file_name)
                files.extend(items)

        else:
            field_storage = web.get_form_value("file")
            if field_storage:
                file_name = web.get_form_value("file_name0")
                if not file_name:
                    file_name = web.get_form_value("filename")

                if not file_name:
                    file_name = self.get_file_name(field_storage)

                files = self.dump(field_storage, file_name)


        if files:
            print("files: ", files)
            return "file_name=%s\n" % ','.join(files)
        else:
            return "NO FILES"



    def get_file_name(self, field_storage):

        # handle some spoofed upload case
        if isinstance(field_storage, basestring):
            return field_storage

        file_name = field_storage.filename

        # depending how the file is uploaded. If it's uploaded thru Python,
        # it has been JSON dumped as unicode code points, so this decode
        # step would be necessary
        try:
            if not Common.IS_Pv3:
                file_name = file_name.decode('unicode-escape')
        except UnicodeEncodeError as e:
            pass
        except UnicodeError as e:
            pass
        file_name = file_name.replace("\\", "/")
        file_name = os.path.basename(file_name)

        # Not sure if this is really needed anymore
        #file_name = File.get_filesystem_name(file_name)

        return file_name



    def dump(self, field_storage, file_name):

        web = WebContainer.get_web()

        ticket = web.get_form_value("transaction_ticket")
        if not ticket:
            security = Environment.get_security()
            ticket = security.get_ticket_key()

        ticket = ticket[:100]


        tmpdir = Environment.get_tmp_dir()
        subdir = web.get_form_value("subdir")
        custom_upload_dir = web.get_form_value("upload_dir")
        if subdir:
            file_dir = "%s/%s/%s/%s" % (tmpdir, "upload", ticket, subdir)
        else:
            file_dir = "%s/%s/%s" % (tmpdir, "upload", ticket)
        
        if custom_upload_dir:
            if subdir:
                file_dir = "%s/%s" % (file_dir, subdir)
            else:
                file_dir = custom_upload_dir

        '''
        If upload method is html5, the action is an empty
        string. Otherwise, action is either 'create' or 'append'.
        '''
        action = web.get_form_value("action")
        html5_mode = False
        if not action:
            html5_mode = True
            action = "create"

        '''
        With some recent change done in cherrypy._cpreqbody line 517, 
        we can use the field storage directly on Linux when the file
        is uploaded in html5 mode.
        TODO: This shortcut cannot be used with upload_multipart.py 
        '''
        if isinstance(field_storage, basestring):
            return
        path = field_storage.get_path()

        # Base 64 encoded files are uploaded and decoded in FileUpload
        base_decode = None
        print("action: ", action)
        if action in ["create", "append"]:
            if os.name == 'nt':
                f = field_storage.file
            else:
                f = open(path, 'rb')
            header = f.read(100)
            f.seek(0)

            #if header.startswith("data:image/png;base64") or header.startswith("data:image/jpeg;base64"):
            if re.search(b"^data:([\w\-\_]+)\/([\w\-\_]+);base64", header):
                base_decode = True
            else:
                base_decode = False
        
            if os.name != 'nt':
                f.close()

        if html5_mode and file_name and path and not base_decode:
            
            '''
            example of path:
                /home/tactic/tactic_temp/temp/tmpTxXIjM 
            example of to_path: 
                /home/tactic/tactic_temp/upload/
                XX-dev-2924f964921857bf239acef4f9bcf3bf/miso_ramen.jpg
            '''

            basename = os.path.basename(path)
            to_path = "%s/%s" % (file_dir, file_name)

            to_dir = os.path.dirname(to_path)
            if not os.path.exists(to_dir):
                os.makedirs(to_dir)

            shutil.move(path, to_path)
            
            '''
            # Close the mkstemp file descriptor 
            fd = field_storage.get_fd()
            if fd: 
                os.close( fd )
            '''
     
            # Because _cpreqbody makes use of mkstemp, the file permissions
            # are set to 600.  This switches to the permissions as defined
            # by the TACTIC users umask
            try:
                current_umask = os.umask(0)
                os.umask(current_umask)
                os.chmod(to_path, 0o666 - current_umask)
            except Exception as e:
                print("WARNING: ", e)

            return [to_path]


        if field_storage == "":
            # for swfupload
            field_storage = web.get_form_value("Filedata")

            if not field_storage:
                file_name = web.get_form_value("Filename")


        # Process and get the uploaded files
        upload = FileUpload()
        if action == "append":
            upload.set_append_mode(True)
            upload.set_create_icon(False)
        elif action == "create":
            upload.set_create_icon(False)
        elif not action:
            # this means that we are accessing from browser.
            return "Upload server"
        else:
            print("WARNING: Upload action '%s' not supported" % action)
            raise TacticException("Upload action '%s' not supported" % action)

        # set the field storage
        if field_storage:
            upload.set_field_storage(field_storage, file_name)
 
        upload.set_file_dir(file_dir)

        # set base64 decode
        upload.set_decode(base_decode)

        upload.execute()
        files = upload.get_files()
        return files






