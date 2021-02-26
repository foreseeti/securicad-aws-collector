from pathlib import Path
from typing import List

import pkg_resources
import setuptools


def get_requirements() -> List[str]:
    reqs_path = Path(__file__).with_name("requirements.in")
    with reqs_path.open(mode="r", encoding="utf-8") as f:
        return [str(req) for req in pkg_resources.parse_requirements(f)]


setuptools.setup(install_requires=get_requirements())
