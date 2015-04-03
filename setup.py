from setuptools import setup

setup(
    name='cbapi2',
    version='0.5',
    packages=['cbapi2'],
    url='https://github.com/redcanaryco/cbapi2',
    license='',
    author='Jason Garman',
    author_email='jason@redcanary.co',
    description='',
    install_requires=[
        'PyYAML', 
        'requests',
        'progressbar',
        'python-cjson',
        'python-dateutil'
    ],
    tests_require=[
        'nose',    
    ],
    test_suite = 'nose.collector'
)
