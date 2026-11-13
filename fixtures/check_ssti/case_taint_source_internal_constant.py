from jinja2 import Template

BANNER = "Hello {{ name }}"


class Greeting(RequestHandler):
    def get(self):
        Template(self.get_argument("tpl")).render()


def render(source):
    return Template(source).render()


def fixed():
    return Template(BANNER).render()
