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

__all__ = ["SyncFilterTest"]

import tacticenv

import unittest

from pyasm.biz import Project
from pyasm.search import SearchType
from pyasm.security import Batch
from pyasm.unittest import UnittestEnvironment


class SyncFilterTest(unittest.TestCase):


    def test_all(my):

        
        Batch()

        test_env = UnittestEnvironment()
        test_env.create()
        try:
            my._test_security()
        finally:
            test_env.delete()

        
    def _test_security(my):

        transaction = '''
<transction>

</transaction>
        '''
        log = SearchType.create("sthpw/transaction_log")
        log.set_value("transaction", transaction)


        from tactic.ui.sync import SyncFilter
        default = "deny"
        sync_filter = SyncFilter(transaction=log, default=default)

        mode = "data"
        #rules = sync_filter.get_sthpw_filter()
        if mode == "config":
            rules = sync_filter.get_project_filter()
            sync_filter.add_rules(rules)



        sync_filter.execute()
        filtered_xml = sync_filter.get_filtered_xml()
        message = sync_filter.get_message()

        print filtered_xml.to_string()




if __name__ == '__main__':
    unittest.main()



