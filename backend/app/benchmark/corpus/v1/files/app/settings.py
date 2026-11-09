"""Application settings for the benchmark fixture.

The credential below is a well-known documentation example, not a live key.
"""

AWS_REGION = "eu-west-1"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def load_settings() -> dict:
    return {"region": AWS_REGION, "key": AWS_ACCESS_KEY_ID}
