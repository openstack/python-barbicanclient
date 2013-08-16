import urllib


def proc_template(template, **kwargs):
    """
    Processes a templated URL by substituting the
    dictionary args and returning the strings.
    """
    return template.format(**dict([(k, urllib.quote(v))
                           for k, v in kwargs.items()]))
