from setuptools import setup, find_packages
import os

with open(os.path.join('version.txt')) as version_file:
    version_from_file = version_file.read().strip()

with open('requirements.txt') as f_required:
    required = f_required.read().splitlines()

with open('test_requirements.txt') as f_tests:
    required_for_tests = f_tests.read().splitlines()


setup(
    name="cloudshell-cp-vcenter",
    author="Quali",
    author_email="support@qualisystems.com",
    description=("This shell enables setting up vCenter as a cloud provider in"
                 "CloudShell. It supports connectivity, deployment and management operations"
                 "used for Cloudshel sanboxes."),
    packages=find_packages(),
    package_data={'': ['*.txt']},
    install_requires=required,
    tests_require=required_for_tests,
    version=version_from_file,
    include_package_data=True,
    keywords = "sandbox cloud virtualization vcenter cmp cloudshell",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: Apache Software License",
    ]

)