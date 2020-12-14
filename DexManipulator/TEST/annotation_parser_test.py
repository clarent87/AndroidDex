import unittest
import os
from dexparser import *


class AnnotationParserTest(unittest.TestCase):
    dex_file_name = ".dex"
    anp = None

    @classmethod
    def setUpClass(cls):
        dp = dexparser.DexParser(AnnotationParserTest.dex_file_name)
        AnnotationParserTest.anp = annotationparser.AnnotationParser(dp.mmap,dp)

    def test_annotations_directory_list(self):
        for x in  self.anp.annotations_directory_list:
            print x
    def test_annotation_set_item_list(self):
        for x in  self.anp.annotation_set_item_list:
            print x
    def test_annotation_set_ref_list(self):
        print "------------------------ref list------------------------"
        for x in  self.anp.annotation_set_ref_list:
            print x
