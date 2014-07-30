############################################################
#
#    Copyright (c) 2011, Southpaw Technology
#                        All Rights Reserved
#
#    PROPRIETARY INFORMATION.  This software is proprietary to
#    Southpaw Technology, and is not to be reproduced, transmitted,
#    or disclosed in any way without written permission.
#
#

__all__ = ['SyncFilter']


import tacticenv

from pyasm.common import Environment, Xml, TacticException
from pyasm.biz import Project
from pyasm.search import SearchType, Search
from pyasm.security import AccessManager

import os, codecs


class SyncFilter(object):

    def __init__(my, **kwargs):
        my.kwargs = kwargs

        my.log = my.kwargs.get("transaction")
        my.rules = my.kwargs.get("rules")
        my.message = ""


    def execute(my):
        log = my.log
        rules = my.rules

        # TODO:
        # Give rules.  Only notes will get through
        # we need hierarchical rules.  This will ensure that only notes
        # for project/assets will pass
        # Here, the second one is much more difficult to do.
        rulesXXX = '''
        <rule group='hierarchy' key='project/asset.sthpw/note' access='allow'/>
        <rule group='hierarchy' key="project/asset.sthpw/note['assigned','beth']" access='allow'/>"
        '''

        access_manager = AccessManager()
        access_manager.add_xml_rules(rules)


        # filter out project
        namespace = log.get_value("namespace")
        key1 = { 'code': namespace }
        key2 = { 'code': '*' }
        keys = [key1, key2]
        if not access_manager.check_access("project", keys, "allow", default="deny"):
            my.filtered_xml = Xml()
            my.filtered_xml.read_string("<transaction/>")
            my.message = "Transaction prevented due to project restriction"
            return


        # filter the transaction against the security model
        xml = log.get_xml_value("transaction")

        my.filtered_xml = Xml()
        my.filtered_xml.create_doc("transaction")
        root2 = my.filtered_xml.get_root_node()

        nodes = xml.get_nodes("transaction/*")
        num_nodes = len(nodes)
        count = 0


        for node in nodes:
            if Xml.get_node_name(node) ==  "sobject":
                search_type = xml.get_attribute(node, "search_type")
                parts = search_type.split("?")
                search_type = parts[0]

                # filter search types
                key1 = { 'code': search_type }
                key2 = { 'code': "*" }
                keys = [ key1, key2 ]
                if not access_manager.check_access("search_type", keys, "allow", default="deny"):
                    continue

                # check hierachical rule
                parent_type = xml.get_attribute(node, "parent_type")
                key = "%s.%s" % (parent_type, search_type)
                
                my.filtered_xml.append_child(root2, node)
                count += 1
                
            else:
                my.filtered_xml.append_child(root2, node)
                count += 1

        if len(nodes) != 0 and len(my.filtered_xml.get_nodes("transaction/*")) == 0:
            my.message = "All actions filtered due to security restrictions (%s actions)" % num_nodes



    def get_filtered_xml(my):
        return my.filtered_xml

    def get_message(my):
        return my.message



    # predefined rule sets to simplify the type of relationship between servers
    def get_config_rules(my, level):
        # allow config
        return '''
        <rule group='search_type' key='config/*' access='allow'/>
        '''

    def get_project_rules(my, level):
        # allow config
        project_code = Project.get_project_code()
        return '''
        <rule group='search_type' key='%s/*' access='allow'/>
        ''' % project_code

    def get_sthpw_rules(my, level):
        # allow config
        project_code = Project.get_project_code()
        return '''
        <rule group='search_type' key='sthpw/*' access='allow'/>
        '''






if __name__ == '__main__':

    from pyasm.security import Batch
    Batch(project_code='new_project')

    filter = SyncFilter()
    filter.execute()




