import re
from django.core.exceptions import ValidationError

def validate_gst(value):
    if not re.match(r'^[A-Z0-9]*$', value):
        raise ValidationError('GST number can only contain uppercase letters and numbers.')
