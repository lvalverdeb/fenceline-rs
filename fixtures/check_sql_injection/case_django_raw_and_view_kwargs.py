from django.views import View
from django.db.models.expressions import RawSQL


class ItemView(View):
    def helper(self):
        pk = self.kwargs["pk"]
        return Item.objects.raw(f"SELECT * FROM items WHERE id = {pk}")

    def other(self, label):
        return Item.objects.annotate(x=RawSQL("SELECT %s" % label, []))


def lambda_handler(event, context):
    name = event["queryStringParameters"]["name"]
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


class Plain:
    def helper(self):
        return Item.objects.raw(f"SELECT * FROM items WHERE id = {self.kwargs['pk']}")
