from lxml import etree

parser = etree.XMLParser(resolve_entities=True)
tree = etree.fromstring(user_xml, parser=parser)
