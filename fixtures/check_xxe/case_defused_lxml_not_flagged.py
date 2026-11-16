from io import BytesIO
from xml.etree.ElementTree import Element, SubElement
from lxml import etree


def read(data):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.parse(BytesIO(data), parser=parser).getroot()


def loose(data):
    return etree.fromstring(data)
