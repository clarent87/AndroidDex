from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput

from dexmodifier import *

"""Test.
class Banana:

    def eat(self):
        pass


class Person:

    def __init__(self):
        self.no_bananas()

    def no_bananas(self):
        self.bananas = []

    def add_banana(self, banana):
        self.bananas.append(banana)

    def eat_bananas(self):
        [banana.eat() for banana in self.bananas]
        self.no_bananas()
"""
"""
    with PyCallGraph(output=graphviz):
        person = Person()
        for a in xrange(10):
            person.add_banana(Banana())
        person.eat_bananas()
"""

def main():
    graphviz = GraphvizOutput()
    graphviz.output_file = 'basic.png'

    dxm = dexmodifier.DexModifier("classes.dex")
    cm = classmethodmodifer.DexModifier("classes_copy.dex")

    with PyCallGraph(output=graphviz):
        cm.get_modified_dex2()
        dxm.get_obfuscated_dex('TargetClass')

if __name__ == '__main__':
    main()
