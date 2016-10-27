
from setuptools import setup


def text(filename):
    with open(filename) as f:
        return f.read()


setup(name='dhcpspoof',
      version='0.1',
      description='Fires a DHCP spoofing attack, for educational pouposes only.',
      long_description=text('README.rst'),
      author='Márcio Balotin',
      author_email='mbalotin@gmail.com',
      url='https://github.com/mbalotin/dhcpspoofing',
      license='MIT',
      packages=[
          'spoofing',
      ],
      install_requires=text('requirements.txt').split('\n'),
      entry_points={
          'console_scripts': [
              'dhcpspoof = spoofing.__main__',
          ]
      },
      include_package_data=True,
      zip_safe=False,
      classifiers=[
          'Development Status :: 1 - Planning',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Topic :: Utilities',
      ])
