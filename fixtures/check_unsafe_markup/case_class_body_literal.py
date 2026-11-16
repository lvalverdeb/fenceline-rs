from django.utils.safestring import mark_safe


EMPTY = mark_safe("&mdash;")


class Column:
    placeholder = mark_safe("&mdash;")
    icon = "<i class='fa'></i>"
    icon_html = mark_safe(icon)
    banner = mark_safe(load_banner())
